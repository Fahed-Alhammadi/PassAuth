package io.passauth.app.ui.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.PasswordHistory
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.theme.PassAuthTheme

/** An item's previous passwords, newest first: masked, with reveal and copy. */
@Composable
fun PasswordHistoryScreen(ctx: UiCtx, id: String) {
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val entry = vault?.get(id)
    LaunchedEffect(vault, entry) { if (vault != null && entry == null) ctx.go(Route.Vault) }
    if (entry == null) return
    val history = PasswordHistory.entries(entry.item.passwordHistory)

    Scaffold(topBar = { PageBar("Password history", onBack = { ctx.go(Route.ItemView(id)) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Earlier passwords of ${entry.item.name.ifEmpty { "this item" }}. PassAuth keeps the last 20.",
                style = MaterialTheme.typography.bodyMedium, color = PassAuthTheme.colors.muted,
            )
            CardSection(PasswordHistory.summary(history.size)) {
                if (history.isEmpty()) {
                    Text("This item has no previous passwords.", modifier = Modifier.padding(vertical = 12.dp))
                }
                history.forEachIndexed { n, change ->
                    if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
                    var show by rememberSaveable("history-$n") { mutableStateOf(false) }
                    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f).semantics(mergeDescendants = true) {}) {
                            Text(
                                if (show) change.password else "••••••••",
                                style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                                modifier = if (show) Modifier else Modifier.semantics { contentDescription = "Password hidden" },
                            )
                            Text(PasswordHistory.changedLabel(change.changedAt), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                        }
                        IconButton(onClick = { show = !show }) {
                            Icon(
                                if (show) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                if (show) "Hide password ${n + 1}" else "Show password ${n + 1}",
                            )
                        }
                        CopyButton(ctx, change.password, "Previous password ${n + 1}")
                    }
                }
            }
        }
    }
}
