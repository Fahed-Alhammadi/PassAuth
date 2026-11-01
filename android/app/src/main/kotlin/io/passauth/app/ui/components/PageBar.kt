package io.passauth.app.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Logout
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.passauth.app.data.MAX_ACCOUNTS
import io.passauth.app.data.Status
import io.passauth.app.data.UrlMatcher
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.theme.PassAuthTheme

/** Page header in the brand's navy: back button or logo, title, actions. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PageBar(title: String, onBack: (() -> Unit)? = null, brand: Boolean = false, actions: @Composable RowScope.() -> Unit = {}) {
    val c = PassAuthTheme.colors
    TopAppBar(
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (brand && onBack == null) {
                    LogoMark(26.dp)
                    Spacer(Modifier.size(10.dp))
                }
                Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis, fontWeight = FontWeight.SemiBold, modifier = Modifier.semantics { heading() })
            }
        },
        navigationIcon = {
            if (onBack != null) {
                IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Outlined.ArrowBack, contentDescription = "Back") }
            }
        },
        actions = actions,
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = c.header,
            titleContentColor = c.onHeader,
            navigationIconContentColor = c.onHeader,
            actionIconContentColor = c.onHeader,
        ),
    )
}

private fun hostOf(server: String) = UrlMatcher.parse(server)?.host ?: server

private fun statusLabel(s: Status) = when (s) {
    Status.Unlocked -> "Unlocked"
    Status.Locked -> "Locked"
    Status.LoggedOut -> "Logged out"
    Status.Setup -> ""
}

/** Account menu: who is signed in, other accounts to switch to, add account, lock, web vault, log out. */
@Composable
fun AccountMenu(ctx: UiCtx) {
    val state = ctx.state
    var open by remember { mutableStateOf(false) }
    IconButton(onClick = { open = true }, modifier = Modifier.semantics { contentDescription = "Account menu: ${state.name.ifEmpty { state.email }}" }) {
        Avatar(initials(state.name, state.email), 32.dp, Modifier.clearAndSetSemantics { })
    }
    DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text(state.name.ifEmpty { state.email }, style = MaterialTheme.typography.titleSmall)
            if (state.name.isNotEmpty()) Text(state.email, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
            Text(hostOf(state.server), style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
        HorizontalDivider()
        state.accounts.filter { it.id != state.activeId }.forEach { a ->
            DropdownMenuItem(
                leadingIcon = { Avatar(initials(a.name, a.email), 28.dp) },
                text = {
                    Column {
                        Text(a.name.ifEmpty { a.email }, maxLines = 1)
                        Text("${hostOf(a.server)} · ${statusLabel(a.status)}", style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
                    }
                },
                onClick = { open = false; ctx.launch { ctx.repo.switchAccount(a.id) } },
            )
        }
        if (state.accounts.size < MAX_ACCOUNTS) {
            DropdownMenuItem(
                leadingIcon = { Icon(Icons.Outlined.Add, null) },
                text = { Text("Add account") },
                onClick = { open = false; ctx.launch { ctx.repo.addAccount() } },
            )
        }
        HorizontalDivider()
        DropdownMenuItem(
            leadingIcon = { Icon(Icons.Outlined.Lock, null) },
            text = { Text("Lock") },
            onClick = { open = false; ctx.launch { ctx.repo.lock() } },
        )
        DropdownMenuItem(
            leadingIcon = { Icon(Icons.AutoMirrored.Outlined.OpenInNew, null) },
            text = { Text("Open web vault") },
            onClick = { open = false; ctx.openUrl(state.server) },
        )
        DropdownMenuItem(
            leadingIcon = { Icon(Icons.AutoMirrored.Outlined.Logout, null, tint = MaterialTheme.colorScheme.error) },
            text = { Text("Log out", color = MaterialTheme.colorScheme.error) },
            onClick = { open = false; ctx.launch { ctx.repo.logout() } },
        )
    }
}
