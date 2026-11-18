package io.passauth.app.ui.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.GroupAdd
import androidx.compose.material.icons.outlined.Policy
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Entry
import io.passauth.app.data.InvitationText
import io.passauth.app.data.ItemKind
import io.passauth.app.data.PolicyFix
import io.passauth.app.data.PolicyRules
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.AccountMenu
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.components.SiteIcon
import io.passauth.app.ui.components.cardSegment
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Radius
import io.passauth.app.ui.theme.Space
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
    val emergencyNotice by ctx.repo.emergencyNotice.collectAsStateWithLifecycle()
    val dismissed by ctx.repo.dismissed.collectAsStateWithLifecycle()
    val violationsByAccount by ctx.repo.violations.collectAsStateWithLifecycle()
    val sharing by ctx.repo.sharing.collectAsStateWithLifecycle()
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
            LazyColumn(contentPadding = PaddingValues(Space.l), modifier = Modifier.fillMaxSize()) {
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
                    // A server this app can't use (it doesn't sign shares): said as it is; the copy on this phone stays readable.
                    val problem = v.syncProblem
                    item {
                        if (problem != null) Alert("$problem Showing the copy of your vault saved on this device.", AlertKind.Error, modifier = Modifier.padding(top = 8.dp))
                        else Alert("You're offline. Showing the copy of your vault saved on this device.", modifier = Modifier.padding(top = 8.dp))
                    }
                }
                // Vaults whose items aren't what the vault's record of changes says (vault manifests): shown, not changed.
                v?.unresolved.orEmpty().forEach { u ->
                    item(key = "manifest:${u.id}") { ManifestWarning(ctx, u, named = (v?.vaults?.size ?: 0) > 1) }
                }
                // Vaults nothing is checked for since the user accepted "no record": one quiet line until a record exists again.
                v?.notChecked.orEmpty().forEach { u ->
                    item(key = "not-checked:${u.id}") { QuietCard(u.name.takeIf { (v?.vaults?.size ?: 0) > 1 }, io.passauth.app.data.Manifests.NOT_CHECKED) }
                }
                // Vaults that hold an item this phone can't open: a notice (nothing is held for it), the items listed below.
                v?.withUnopenable.orEmpty().forEach { u ->
                    item(key = "unopenable:${u.id}") {
                        WarningCard(ctx, u.name.takeIf { (v?.vaults?.size ?: 0) > 1 }, io.passauth.app.data.Manifests.UNOPENABLE)
                    }
                }
                // Items that don't open: nothing to show of them, but someone who can edit the vault can delete them for good.
                v?.unopenable.orEmpty().forEach { row ->
                    val vault = v?.vaults?.firstOrNull { it.id == row.vaultId } ?: return@forEach
                    item(key = "unopenable-item:${row.id}") {
                        val M = io.passauth.app.data.Manifests
                        // A vault whose record doesn't match is reviewed first ("Use the server's copy"); view-only members can't delete.
                        val canDelete = vault.role != io.passauth.app.data.Role.Read && vault.manifest != io.passauth.app.data.ManifestState.Unresolved
                        val place = if (row.trashed) "In the trash of ${vault.name}." else "In ${vault.name}."
                        WarningCard(
                            ctx, M.UNOPENABLE_ITEM, row.name?.let { "Last saved here as $it. $place" } ?: place,
                            action = M.DELETE_FOR_GOOD.takeIf { canDelete },
                            confirmTitle = "${M.DELETE_FOR_GOOD}?", confirmSubtitle = vault.name, confirmBody = M.DELETE_FOR_GOOD_CONFIRM,
                        ) {
                            ctx.repo.deleteUnopenable(row)
                            ctx.notify("Item deleted.")
                        }
                    }
                }
                // Items a newer app saved that this one can't read: listed, nothing to do but update.
                v?.newer.orEmpty().forEach { row ->
                    val vault = v?.vaults?.firstOrNull { it.id == row.vaultId } ?: return@forEach
                    item(key = "newer-item:${row.id}") {
                        val O = io.passauth.app.data.ItemOpening
                        QuietCard(O.NEWER_ITEM, if ((v?.vaults?.size ?: 0) > 1) "${O.NEWER_NOTE} In ${vault.name}." else O.NEWER_NOTE)
                    }
                }
                // This phone's own record of the vaults can't be read, again and again: said, with the way out.
                if (v?.memoryUnreadable == true) {
                    item(key = "memory-unreadable") {
                        val M = io.passauth.app.data.Manifests
                        WarningCard(
                            ctx, null, M.MEMORY_UNREADABLE,
                            action = M.RESET_MEMORY, confirmTitle = "${M.RESET_MEMORY}?", confirmSubtitle = null, confirmBody = M.RESET_MEMORY_CONFIRM,
                        ) { ctx.repo.resetDeviceMemory() }
                    }
                }
                // The server sent older versions of items than this phone saw (item edit counters).
                v?.rollbackNotice?.let { notice ->
                    item { Alert(notice, AlertKind.Error, modifier = Modifier.padding(top = 8.dp)) }
                }
                // Vaults shared with the account, waiting for an answer: one quiet line (dismissed until a new one arrives).
                val invitations = v?.invitations.orEmpty()
                val inviteKey = "inv:" + InvitationText.noticeKey(invitations)
                val inviteText = InvitationText.notice(invitations)
                if (inviteText != null && inviteKey !in dismissed) {
                    item(key = "notice:invitations") {
                        NoticeCard(
                            Icons.Outlined.GroupAdd,
                            listOf(NoticeLine(inviteText, InvitationText.noticeAction(invitations)) { ctx.go(Route.Invitations(fromVault = true)) }),
                            onDismiss = { ctx.repo.dismissNotice(inviteKey) },
                        )
                    }
                }
                // Signed sharing: a shared vault PassAuth refused, someone's keys changed, sharing paused, or the known keys rolled back.
                val sharingLines = buildList {
                    if (sharing.paused) add(io.passauth.app.data.SignedSharing.PAUSED)
                    sharing.pinsProblem?.let { add(it) }
                    if (sharing.memoryMissing) add(io.passauth.app.data.SignedSharing.MEMORY_MISSING)
                    sharing.changed.forEach { add(it.text) }
                    if (sharing.consent.isNotEmpty()) {
                        add(
                            if (sharing.consent.size == 1) io.passauth.app.data.SignedSharing.consentTitle(sharing.consent[0].name) + ". Accept it only if you expected it."
                            else "Your server added ${sharing.consent.size} vaults to your account. Accept them only if you expected them.",
                        )
                    }
                    if (sharing.refused.isNotEmpty()) add(io.passauth.app.data.SignedSharing.REFUSED)
                }
                if (sharingLines.isNotEmpty() && sharing.noticeKey !in dismissed) {
                    item(key = "notice:sharing") {
                        NoticeCard(
                            Icons.Outlined.Policy,
                            sharingLines.mapIndexed { n, text -> NoticeLine(text, if (n == sharingLines.lastIndex) "Review" else null) { ctx.go(Route.Settings("sharing")) } },
                            onDismiss = { ctx.repo.dismissNotice(sharing.noticeKey) },
                        )
                    }
                }
                // The emergency contact list from the server can't be trusted (older than one seen here, or unreadable).
                emergencyNotice?.let { text ->
                    val key = "emg:$text"
                    if (key !in dismissed) {
                        item(key = "notice:emergency") {
                            NoticeCard(
                                Icons.Outlined.Policy,
                                listOf(NoticeLine(text, "Review the list") { ctx.go(Route.Settings("emergency")) }),
                                onDismiss = { ctx.repo.dismissNotice(key) },
                            )
                        }
                    }
                }
                // What the account still has to change for the server's policies.
                val violations = violationsByAccount[ctx.state.activeId].orEmpty()
                val policyKey = "pol:${ctx.state.activeId}:" + PolicyRules.violationsKey(violations)
                if (violations.isNotEmpty() && policyKey !in dismissed) {
                    item(key = "notice:policies") {
                        NoticeCard(
                            Icons.Outlined.Policy,
                            PolicyRules.notices(violations).map { n ->
                                NoticeLine(n.text, n.action) {
                                    ctx.go(Route.Settings(if (n.fix == PolicyFix.TwoStep) "two-step" else "password"))
                                }
                            },
                            onDismiss = { ctx.repo.dismissNotice(policyKey) },
                        )
                    }
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
                        Column(Modifier.fillMaxWidth().padding(vertical = Space.xl), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("No items match.", style = MaterialTheme.typography.bodyLarge)
                            Text("Try another search, or clear the filters.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.size(Space.s))
                            TextButton(onClick = { setFilter(ListFilter()) }) { Text("Clear search and filters") }
                        }
                    }
                } else {
                    val favorites = all.filter { it.item.favorite }
                    if (favorites.isNotEmpty()) section(ctx, "Favorites", favorites)
                    section(ctx, "All items", all) {
                        Column(Modifier.fillMaxWidth().padding(vertical = Space.xl), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("Your vault is empty.", style = MaterialTheme.typography.bodyLarge)
                            Text("Add your first login to fill it in apps and websites.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.size(Space.l))
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
        Row(Modifier.fillMaxWidth().padding(top = Space.l, bottom = Space.s, start = Space.xs, end = Space.xs)) {
            Text(title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f).semantics { heading() })
            Text("${items.size}", style = MaterialTheme.typography.labelLarge, color = PassAuthTheme.colors.muted, modifier = Modifier.semantics { contentDescription = if (items.size == 1) "1 item" else "${items.size} items" })
        }
    }
    if (items.isEmpty()) {
        if (empty != null) item(key = "e:$title") { empty() }
    } else {
        // One grouped card per section; each row draws its own part of it, so long lists stay lazy.
        itemsIndexed(items, key = { _, it -> "$title:${it.entry.id}" }) { n, it -> ItemRow(ctx, it, first = n == 0, last = n == items.lastIndex) }
    }
}

@Composable
private fun ItemRow(ctx: UiCtx, s: ItemSummary, first: Boolean, last: Boolean) {
    val open = { ctx.go(Route.ItemView(s.entry.id)) }
    val login = s.item.login
    var copyMenu by remember { mutableStateOf(false) }
    var moreMenu by remember { mutableStateOf(false) }
    val quiet = PassAuthTheme.colors.muted
    // Large text: the name gets the room, and "Open website" moves into the More menu.
    val roomy = LocalDensity.current.fontScale < 1.3f
    Row(
        Modifier.fillMaxWidth()
            .cardSegment(first, last, MaterialTheme.colorScheme.surfaceContainer, PassAuthTheme.colors.line, dividerInset = Space.l + 40.dp + Space.m)
            .clickable(onClick = open)
            .heightIn(min = 64.dp)
            .padding(start = Space.l, end = Space.xs, top = Space.s, bottom = Space.s),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        SiteIcon(s.host, s.name, ctx.state.server, ctx.state.showSiteIcons, ctx.graph.icons, 40.dp, login = s.item.kind == io.passauth.app.data.ItemKind.Login)
        Column(Modifier.weight(1f).padding(start = Space.m, end = Space.xs)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(s.name, style = MaterialTheme.typography.bodyLarge, maxLines = if (roomy) 1 else 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (s.item.favorite) Icon(Icons.Filled.Star, "Favorite", Modifier.padding(start = Space.xs).size(14.dp), tint = MaterialTheme.colorScheme.primary)
            }
            if (s.subtitle.isNotEmpty()) {
                Text(s.subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        // Quick actions stay on the row, quiet: the row itself is the primary action.
        if (s.url.isNotEmpty() && roomy) {
            QuietIconButton(Icons.AutoMirrored.Outlined.OpenInNew, "Open ${s.host}", quiet) { ctx.openUrl(s.url) }
        }
        if (login != null && (login.username.isNotEmpty() || login.password.isNotEmpty() || login.totp != null)) {
            Box {
                QuietIconButton(Icons.Outlined.ContentCopy, "Copy from ${s.name}", quiet) { copyMenu = true }
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
            QuietIconButton(Icons.Outlined.MoreVert, "More options for ${s.name}", quiet) { moreMenu = true }
            DropdownMenu(expanded = moreMenu, onDismissRequest = { moreMenu = false }) {
                DropdownMenuItem(text = { Text("View") }, onClick = { moreMenu = false; open() })
                DropdownMenuItem(text = { Text("Edit") }, onClick = { moreMenu = false; ctx.go(Route.Edit(s.entry.id)) })
                if (s.url.isNotEmpty() && !roomy) {
                    DropdownMenuItem(text = { Text("Open ${s.host}") }, onClick = { moreMenu = false; ctx.openUrl(s.url) })
                }
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

/**
 * The warning of a vault whose items don't match its manifest, with the deliberate way out ("Use the
 * server's copy", confirmed in a sheet): for everyone when this phone alone can accept what the
 * server shows, else for people who can edit the vault (a new record is written); view-only members
 * are told who can. Never dismissible: the vault isn't changed while it shows.
 */
@Composable
private fun ManifestWarning(ctx: UiCtx, vault: io.passauth.app.data.VaultInfo, named: Boolean) {
    val m = io.passauth.app.data.Manifests
    val offered = vault.manifestAcceptable || vault.role != io.passauth.app.data.Role.Read
    WarningCard(
        ctx, vault.name.takeIf { named }, m.WARNING,
        note = m.READERS.takeIf { !offered },
        action = m.USE_SERVER_COPY.takeIf { offered },
        // The server shows no record at all for a vault that had one: accepting means no checks, and the sheet says that.
        confirmTitle = m.CONFIRM_TITLE, confirmSubtitle = vault.name, confirmBody = if (vault.manifestNoRecord) m.CONFIRM_NO_RECORD else m.CONFIRM_BODY,
    ) { ctx.repo.useServerCopy(vault.id, noRecord = vault.manifestNoRecord) }
}

/** A quiet standing line above the items (not a warning, nothing to do about it here): an optional [heading] and the [text]. */
@Composable
private fun QuietCard(heading: String?, text: String) {
    Surface(
        shape = RoundedCornerShape(Radius.card),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, PassAuthTheme.colors.line),
        modifier = Modifier.fillMaxWidth().padding(top = Space.s),
    ) {
        Column(Modifier.padding(Space.m)) {
            if (heading != null) Text(heading, style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * A standing warning above the items (never dismissible): an optional [heading], the [text], an
 * optional [note], and an optional [action] that is confirmed in a sheet ([confirmTitle],
 * [confirmBody]) before [run].
 */
@Composable
private fun WarningCard(
    ctx: UiCtx,
    heading: String?,
    text: String,
    note: String? = null,
    action: String? = null,
    confirmTitle: String = "",
    confirmSubtitle: String? = null,
    confirmBody: String = "",
    run: suspend () -> Unit = {},
) {
    var confirm by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = RoundedCornerShape(Radius.control),
        modifier = Modifier.fillMaxWidth().padding(top = Space.s),
    ) {
        Column(Modifier.padding(start = Space.m, end = Space.m, top = Space.m, bottom = if (action != null) Space.xs else Space.m)) {
            if (heading != null) Text(heading, style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
            Text(text, style = MaterialTheme.typography.bodyMedium)
            if (note != null) Text(note, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = Space.s))
            if (action != null) {
                TextButton(onClick = { confirm = true }, enabled = !busy, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(action, color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }
        }
    }
    if (confirm && action != null) {
        io.passauth.app.ui.components.DecisionSheet(
            onDismiss = { confirm = false },
            title = confirmTitle,
            subtitle = confirmSubtitle,
            actions = {
                io.passauth.app.ui.components.PrimaryButton(action, {
                    confirm = false
                    busy = true
                    ctx.launch {
                        try {
                            run()
                        } finally {
                            busy = false
                        }
                    }
                }, danger = true)
                io.passauth.app.ui.components.QuietActions { io.passauth.app.ui.components.QuietButton("Cancel", { confirm = false }) }
            },
        ) { io.passauth.app.ui.components.PromptText(confirmBody) }
    }
}

/** One line of a [NoticeCard], with the action that deals with it (none: [action] null). */
private class NoticeLine(val text: String, val action: String?, val onAction: () -> Unit)

/** A quiet, dismissible notice above the items: icon, its lines with their actions, and a close mark. */
@Composable
private fun NoticeCard(icon: androidx.compose.ui.graphics.vector.ImageVector, lines: List<NoticeLine>, onDismiss: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(Radius.card),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, PassAuthTheme.colors.line),
        modifier = Modifier.fillMaxWidth().padding(top = Space.s),
    ) {
        Row(Modifier.padding(start = Space.l, top = Space.s, bottom = Space.xs), verticalAlignment = Alignment.Top) {
            Icon(icon, null, Modifier.padding(top = Space.s).size(20.dp), tint = MaterialTheme.colorScheme.primary)
            Column(Modifier.weight(1f).padding(start = Space.m, top = Space.s)) {
                lines.forEach { line ->
                    Text(line.text, style = MaterialTheme.typography.bodyMedium)
                    if (line.action != null) {
                        TextButton(onClick = line.onAction, modifier = Modifier.heightIn(min = 48.dp)) { Text(line.action) }
                    } else {
                        Spacer(Modifier.size(Space.s))
                    }
                }
            }
            IconButton(onClick = onDismiss) { Icon(Icons.Outlined.Close, contentDescription = "Dismiss", tint = PassAuthTheme.colors.muted) }
        }
    }
}

/** A trailing row action: a 20 dp glyph in a 44 × 48 dp target, in the quiet colour. */
@Composable
private fun QuietIconButton(icon: androidx.compose.ui.graphics.vector.ImageVector, description: String, tint: androidx.compose.ui.graphics.Color, onClick: () -> Unit) {
    IconButton(onClick = onClick, modifier = Modifier.size(width = 44.dp, height = 48.dp)) {
        Icon(icon, description, Modifier.size(20.dp), tint = tint)
    }
}
