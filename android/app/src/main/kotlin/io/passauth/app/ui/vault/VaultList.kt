package io.passauth.app.ui.vault

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Entry
import io.passauth.app.data.ItemKind
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.AccountMenu
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.components.SiteIcon
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.core.totpCode
import kotlinx.coroutines.launch

data class ListFilter(
    val query: String = "",
    val kind: ItemKind? = null,
    /** null = any, "" = no folder. */
    val folder: String? = null,
    val favorites: Boolean = false,
) {
    val active get() = query.isNotBlank() || kind != null || folder != null || favorites
}

/** List row data, like the extension's `ItemSummary`. */
data class ItemSummary(
    val entry: Entry,
    val name: String,
    val subtitle: String,
    val host: String,
    val url: String,
) {
    val item get() = entry.item

    companion object {
        fun of(e: Entry): ItemSummary {
            val i = e.item
            val host = i.siteHost
            val subtitle = i.login?.username?.takeIf { it.isNotEmpty() }
                ?: host.ifEmpty { null }
                ?: i.card?.number?.takeIf { it.length >= 4 }?.let { "•••• ${it.takeLast(4)}" }
                ?: i.notes.lineSequence().firstOrNull().orEmpty().take(50)
            val url = i.login?.urls?.firstOrNull { it.match != io.passauth.app.data.UrlMatch.Regex && Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(it.url) }?.url
                ?: if (host.isNotEmpty()) "https://$host" else ""
            return ItemSummary(e, i.name.ifEmpty { "Untitled" }, subtitle, host, url)
        }
    }
}

fun currentTotp(secret: String) = totpCode(secret, (System.currentTimeMillis() / 1000).toULong())

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultListScreen(ctx: UiCtx, filter: ListFilter, setFilter: (ListFilter) -> Unit) {
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    var showFilter by rememberSaveable { mutableStateOf(filter.kind != null || filter.folder != null || filter.favorites) }
    var refreshing by remember { mutableStateOf(false) }
    var newMenu by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            PageBar("Vault", brand = true) {
                Box {
                    IconButton(onClick = { newMenu = true }) { Icon(Icons.Outlined.Add, contentDescription = "New item") }
                    DropdownMenu(expanded = newMenu, onDismissRequest = { newMenu = false }) {
                        ItemKind.entries.forEach { k ->
                            DropdownMenuItem(text = { Text(k.label) }, onClick = { newMenu = false; ctx.go(Route.New(k)) })
                        }
                    }
                }
                AccountMenu(ctx)
            }
        },
    ) { padding ->
        val v = vault
        val all = remember(v) { v?.entries.orEmpty().map(ItemSummary::of) }
        val folders = remember(v) { v?.folders.orEmpty() }
        PullToRefreshBox(
            isRefreshing = refreshing,
            onRefresh = {
                refreshing = true
                scope.launch {
                    try {
                        ctx.repo.sync()
                    } catch (e: Exception) {
                        ctx.notify("Sync failed: ${errorMessage(e)}")
                    }
                    refreshing = false
                }
            },
            modifier = Modifier.padding(padding).fillMaxSize(),
        ) {
            LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxSize()) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = filter.query,
                            onValueChange = { setFilter(filter.copy(query = it)) },
                            placeholder = { Text("Search vault") },
                            leadingIcon = { Icon(Icons.Outlined.Search, null) },
                            trailingIcon = {
                                if (filter.query.isNotEmpty()) {
                                    IconButton(onClick = { setFilter(filter.copy(query = "")) }) { Icon(Icons.Outlined.Close, "Clear search") }
                                }
                            },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        IconButton(onClick = { showFilter = !showFilter }) {
                            Icon(
                                Icons.Outlined.FilterList, contentDescription = "Filters",
                                tint = if (showFilter) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                if (showFilter) {
                    item {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 4.dp)) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                SelectField(
                                    "Type", listOf<Pair<ItemKind?, String>>(null to "All types") + ItemKind.entries.map { it to it.label },
                                    filter.kind, { setFilter(filter.copy(kind = it)) }, Modifier.weight(1f),
                                )
                                SelectField(
                                    "Folder", listOf<Pair<String?, String>>(null to "All folders", "" to "No folder") + folders.map { it to it },
                                    filter.folder, { setFilter(filter.copy(folder = it)) }, Modifier.weight(1f),
                                )
                            }
                            FilterChip(
                                selected = filter.favorites,
                                onClick = { setFilter(filter.copy(favorites = !filter.favorites)) },
                                label = { Text("Favorites") },
                                leadingIcon = { Icon(if (filter.favorites) Icons.Filled.Star else Icons.Outlined.StarBorder, null, Modifier.size(18.dp)) },
                            )
                        }
                    }
                }
                if (v?.offline == true) {
                    item { Alert("You're offline. Showing the copy of your vault saved on this device.", modifier = Modifier.padding(top = 8.dp)) }
                }
                if (v == null) return@LazyColumn
                if (filter.active) {
                    val q = filter.query.trim().lowercase()
                    val found = all.filter { s ->
                        (q.isEmpty() || s.name.lowercase().contains(q) || s.subtitle.lowercase().contains(q) || s.host.contains(q)) &&
                            (filter.kind == null || s.item.kind == filter.kind) &&
                            (filter.folder == null || (s.item.folder ?: "") == filter.folder) &&
                            (!filter.favorites || s.item.favorite)
                    }
                    section(ctx, if (q.isNotEmpty()) "Search results" else "Filtered items", found) {
                        Text("No items match. Try another search or clear the filters.", color = PassAuthTheme.colors.muted, modifier = Modifier.padding(vertical = 16.dp))
                    }
                } else {
                    val favorites = all.filter { it.item.favorite }
                    if (favorites.isNotEmpty()) section(ctx, "Favorites", favorites)
                    section(ctx, "All items", all) {
                        Column(Modifier.fillMaxWidth().padding(vertical = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("Your vault is empty.", color = PassAuthTheme.colors.muted)
                            Spacer(Modifier.size(12.dp))
                            Button(onClick = { ctx.go(Route.New(ItemKind.Login)) }) {
                                Icon(Icons.Outlined.Add, null)
                                Spacer(Modifier.size(6.dp))
                                Text("New login")
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun LazyListScope.section(ctx: UiCtx, title: String, items: List<ItemSummary>, empty: (@Composable () -> Unit)? = null) {
    item(key = "h:$title") {
        Row(Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 4.dp, start = 4.dp, end = 4.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, color = PassAuthTheme.colors.muted, modifier = Modifier.weight(1f))
            Text("${items.size}", style = MaterialTheme.typography.labelMedium, color = PassAuthTheme.colors.muted)
        }
    }
    if (items.isEmpty()) {
        if (empty != null) item(key = "e:$title") { empty() }
    } else {
        items(items, key = { "$title:${it.entry.id}" }) { ItemRow(ctx, it) }
    }
}

@Composable
private fun ItemRow(ctx: UiCtx, s: ItemSummary) {
    val open = { ctx.go(Route.ItemView(s.entry.id)) }
    val login = s.item.login
    var copyMenu by remember { mutableStateOf(false) }
    var moreMenu by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().clickable(onClick = open).padding(vertical = 8.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SiteIcon(s.host, s.name, ctx.state.server, ctx.state.settings.showIcons, ctx.graph.icons)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(s.name, style = MaterialTheme.typography.bodyLarge, maxLines = if (LocalDensity.current.fontScale > 1.3f) 2 else 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (s.item.favorite) Icon(Icons.Filled.Star, "Favorite", Modifier.padding(start = 4.dp).size(14.dp), tint = MaterialTheme.colorScheme.primary)
            }
            if (s.subtitle.isNotEmpty()) {
                Text(s.subtitle, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        if (s.url.isNotEmpty()) {
            IconButton(onClick = { ctx.openUrl(s.url) }) { Icon(Icons.AutoMirrored.Outlined.OpenInNew, "Open ${s.host}") }
        }
        if (login != null && (login.username.isNotEmpty() || login.password.isNotEmpty() || login.totp != null)) {
            Box {
                IconButton(onClick = { copyMenu = true }) { Icon(Icons.Outlined.ContentCopy, "Copy from ${s.name}") }
                DropdownMenu(expanded = copyMenu, onDismissRequest = { copyMenu = false }) {
                    if (login.username.isNotEmpty()) {
                        DropdownMenuItem(text = { Text("Copy username") }, onClick = { copyMenu = false; ctx.copy(login.username, "Username") })
                    }
                    if (login.password.isNotEmpty()) {
                        DropdownMenuItem(text = { Text("Copy password") }, onClick = { copyMenu = false; ctx.copy(login.password, "Password") })
                    }
                    login.totp?.takeIf { it.isNotBlank() }?.let { secret ->
                        DropdownMenuItem(text = { Text("Copy verification code") }, onClick = {
                            copyMenu = false
                            ctx.launch { ctx.copy(currentTotp(secret).code, "Verification code") }
                        })
                    }
                }
            }
        }
        Box {
            IconButton(onClick = { moreMenu = true }) { Icon(Icons.Outlined.MoreVert, "More options for ${s.name}") }
            DropdownMenu(expanded = moreMenu, onDismissRequest = { moreMenu = false }) {
                DropdownMenuItem(text = { Text("View") }, onClick = { moreMenu = false; open() })
                DropdownMenuItem(text = { Text("Edit") }, onClick = { moreMenu = false; ctx.go(Route.Edit(s.entry.id)) })
                DropdownMenuItem(
                    text = { Text(if (s.item.favorite) "Remove from favorites" else "Add to favorites") },
                    onClick = {
                        moreMenu = false
                        ctx.launch {
                            ctx.repo.setFavorite(s.entry, !s.item.favorite)
                            ctx.notify(if (s.item.favorite) "Removed from favorites." else "Added to favorites.")
                        }
                    },
                )
            }
        }
    }
}
