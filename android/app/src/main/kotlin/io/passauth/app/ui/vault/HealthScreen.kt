package io.passauth.app.ui.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.HealthAndSafety
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Entry
import io.passauth.app.data.HealthReport
import io.passauth.app.data.HealthSession
import io.passauth.app.data.HealthSession.Availability
import io.passauth.app.data.HealthSession.Status
import io.passauth.app.data.HealthText
import io.passauth.app.data.ItemKind
import io.passauth.app.data.PasswordHealth
import io.passauth.app.data.Role as VaultRole
import io.passauth.app.data.VaultData
import io.passauth.app.ui.HEALTH
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.GroupLabel
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.SiteIcon
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.cardSegment
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Radius
import io.passauth.app.ui.theme.Space
import io.passauth.core.estimateBits
import java.text.Collator
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date
import kotlinx.coroutines.launch

// Settings → Password health and the password notes on an item's page, as in the web vault
// (`pages/Health.tsx`); the rules are in data/PasswordHealth.kt, the session in data/HealthSession.kt.

private const val INTRO = "Find the logins to fix first: passwords exposed in a data breach, used for more than one login, or easy to guess. " +
    "Weak and reused passwords are found in this app, without sending anything."

private fun fmt(n: Int): String = NumberFormat.getIntegerInstance().format(n)

/** Names compared as the web vault does (`localeCompare`, base sensitivity), "Untitled" for none. */
private val byName: Comparator<Entry> = Collator.getInstance().apply { strength = Collator.PRIMARY }.let { c ->
    Comparator { a, b -> c.compare(a.item.name.ifEmpty { "Untitled" }, b.item.name.ifEmpty { "Untitled" }) }
}

private fun passwordOf(e: Entry) = e.item.login?.password.orEmpty()

/**
 * Weak, reused and exposed passwords across every vault the user can read. Rows open the login: in
 * its editor when the user can change it (saving comes back here), else its page.
 */
@Composable
fun HealthScreen(ctx: UiCtx) {
    val health = ctx.graph.health
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val check by health.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { health.loadAvailability() }
    Scaffold(topBar = { PageBar("Password health", onBack = { ctx.go(Route.Settings()) }) }) { padding ->
        val v = vault ?: return@Scaffold
        val report = remember(v.entries) { health.report(v) }
        val results = check.results
        val exposed = remember(report, results) {
            if (results == null) emptyList()
            else report.logins.filter { (results[passwordOf(it)] ?: 0) > 0 }
                .sortedWith(compareByDescending<Entry> { results[passwordOf(it)] ?: 0 }.then(byName))
        }
        val unchecked = remember(report, results) { results?.let { r -> report.logins.count { passwordOf(it) !in r } } ?: 0 }
        val reusedLogins = report.reused.sumOf { it.size }
        val weak = remember(report) { report.weak.sortedWith(byName) }
        LazyColumn(Modifier.padding(padding).fillMaxSize(), contentPadding = PaddingValues(Space.l)) {
            item(key = "intro") {
                Text(INTRO, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (report.logins.isEmpty()) {
                item(key = "empty") { EmptyHealth(ctx) }
                return@LazyColumn
            }
            item(key = "summary") { Summary(check, report, exposed.size, reusedLogins) }

            item(key = "exposed-title") {
                SectionTitle(
                    "Exposed in data breaches",
                    badge = results?.let { if (exposed.isEmpty()) "None found" else fmt(exposed.size) },
                    tone = if (exposed.isEmpty()) PassAuthTheme.colors.ok else PassAuthTheme.colors.warn,
                )
            }
            item(key = "exposed") { ExposedCard(ctx, check, exposed.size, unchecked, report.logins.size) }
            rows(ctx, v, "x", exposed) { HealthText.timesSeen(results?.get(passwordOf(it)) ?: 0) }

            item(key = "reused-title") { SectionTitle("Reused passwords", badge = if (reusedLogins > 0) fmt(reusedLogins) else null, tone = null) }
            item(key = "reused") {
                Explained("When one site leaks a password that other logins use too, all of them are at risk. Give each login its own password.") {
                    if (report.reused.isEmpty()) AllClear("No reused passwords", "Every login has its own password.")
                }
            }
            report.reused.forEachIndexed { n, group ->
                item(key = "r$n-title") {
                    GroupLabel("Same password in ${HealthText.count(group.size, "login", "logins")}", Modifier.padding(top = Space.l))
                }
                rows(ctx, v, "r$n", group.sortedWith(byName))
            }

            item(key = "weak-title") { SectionTitle("Weak passwords", badge = if (weak.isNotEmpty()) fmt(weak.size) else null, tone = null) }
            item(key = "weak") {
                Explained("These passwords are short or use few kinds of characters, so they're easy to guess. Replace them with generated ones.") {
                    if (weak.isEmpty()) AllClear("No weak passwords", "Every password is long and varied enough.")
                }
            }
            rows(ctx, v, "w", weak)
        }
    }
}

/** The logins of a section as one grouped card, a row each (lazy). */
private fun LazyListScope.rows(ctx: UiCtx, v: VaultData, section: String, entries: List<Entry>, trail: ((Entry) -> String)? = null) {
    itemsIndexed(entries, key = { _, e -> "$section:${e.id}" }) { n, e ->
        HealthRow(ctx, v, e, first = n == 0, last = n == entries.lastIndex, trail = trail?.invoke(e))
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Summary(check: HealthSession.State, report: HealthReport<Entry>, exposed: Int, reusedLogins: Int) {
    val perRow = if (LocalDensity.current.fontScale >= 1.5f) 1 else 2
    val warn = PassAuthTheme.colors.warn
    FlowRow(
        Modifier.fillMaxWidth().padding(top = Space.l),
        maxItemsInEachRow = perRow,
        horizontalArrangement = Arrangement.spacedBy(Space.s),
        verticalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        val tile = Modifier.weight(1f)
        if (check.results != null) {
            Stat(fmt(exposed), "Exposed", if (exposed > 0) MaterialTheme.colorScheme.error else null, tile)
        } else if (check.availability != Availability.Off && check.availability != Availability.Unknown) {
            Stat("–", "Exposed: not checked yet", null, tile)
        }
        Stat(fmt(reusedLogins), "Reused", if (reusedLogins > 0) warn else null, tile)
        Stat(fmt(report.weak.size), "Weak", if (report.weak.isNotEmpty()) warn else null, tile)
        Stat(fmt(report.logins.size), if (report.logins.size == 1) "Login with a password" else "Logins with a password", null, tile)
    }
}

/** A summary number. */
@Composable
private fun Stat(value: String, label: String, tone: Color?, modifier: Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(Radius.control),
        border = BorderStroke(1.dp, PassAuthTheme.colors.line),
        modifier = modifier.clearAndSetSemantics { contentDescription = if (value == "–") label else "$label: $value" },
    ) {
        Column(Modifier.padding(horizontal = Space.m, vertical = Space.s)) {
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold, color = tone ?: MaterialTheme.colorScheme.onSurface)
            Text(label, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
    }
}

/** A section's heading, with its count. */
@Composable
private fun SectionTitle(title: String, badge: String?, tone: Color?) {
    Row(
        Modifier.fillMaxWidth().padding(top = Space.xl, bottom = Space.s, start = Space.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.s),
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.semantics { heading() })
        if (badge != null) {
            val color = tone ?: PassAuthTheme.colors.muted
            Surface(shape = RoundedCornerShape(50), color = color.copy(alpha = 0.14f), contentColor = color) {
                Text(
                    badge, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                        .semantics { contentDescription = if (badge == "None found") "none found" else "$badge logins" },
                )
            }
        }
    }
}

/** A section's card: what it means, then what's below it. */
@Composable
private fun Explained(text: String, content: @Composable () -> Unit) {
    GroupCard {
        Column(Modifier.padding(horizontal = Space.l, vertical = Space.m), verticalArrangement = Arrangement.spacedBy(Space.m)) {
            Text(text, style = MaterialTheme.typography.bodyMedium)
            content()
        }
    }
}

@Composable
private fun ExposedCard(ctx: UiCtx, check: HealthSession.State, exposed: Int, unchecked: Int, total: Int) {
    val health = ctx.graph.health
    val scope = rememberCoroutineScope()
    val checking = check.status == Status.Checking
    val allowed = check.availability == Availability.On
    // Screen readers hear the progress in steps of a quarter, then the outcome (a live region).
    val announcement = when (check.status) {
        Status.Checking -> HealthText.progress(check.done, check.total)
        Status.Done -> HealthText.finished(exposed)
        Status.Failed -> check.error.orEmpty()
        Status.Idle -> ""
    }
    Explained("Attackers try passwords from known breaches first, on every site. Change these even if they look strong.") {
        when (check.availability) {
            Availability.Off, Availability.Unknown -> {
                Text(
                    if (check.availability == Availability.Off) HealthText.NOT_ALLOWED else HealthText.UNAVAILABLE,
                    style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                )
                if (check.availability == Availability.Unknown) {
                    TextButton(onClick = { scope.launch { health.loadAvailability() } }) { Text("Try again") }
                }
            }
            Availability.Loading, Availability.On -> Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(Space.s)) {
                Icon(Icons.Outlined.Shield, null, Modifier.size(18.dp), tint = PassAuthTheme.colors.ok)
                Text(HealthText.PRIVACY, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        if (allowed && check.results == null) {
            Button(onClick = health::check, enabled = !checking, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.HealthAndSafety, null, Modifier.size(18.dp))
                Spacer(Modifier.size(Space.s))
                Text(if (checking) "Checking…" else if (check.status == Status.Failed) "Try again" else "Check for exposed passwords")
            }
        }
        if (checking) {
            val fraction = if (check.total > 0) check.done.toFloat() / check.total else 0f
            Column(
                Modifier.fillMaxWidth().clearAndSetSemantics {
                    contentDescription = "Breach check"
                    progressBarRangeInfo = ProgressBarRangeInfo(fraction, 0f..1f)
                },
                verticalArrangement = Arrangement.spacedBy(Space.xs),
            ) {
                LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                Text(
                    if (check.total > 0) "Checked ${fmt(check.done)} of ${HealthText.count(check.total, "password", "passwords")}" else "Starting…",
                    style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                )
            }
        }
        val error = check.error
        if (check.status == Status.Failed && error != null) Alert(error, AlertKind.Error)
        if (check.results != null) {
            if (exposed == 0 && unchecked < total) AllClear("No exposed passwords found", "None of the checked passwords appear in known data breaches.")
            if (allowed) {
                OutlinedButton(onClick = health::check, enabled = !checking) { Text(if (checking) "Checking…" else "Check again") }
            }
            val at = check.checkedAt?.let { "Last checked at ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(it))}. " }.orEmpty()
            val changed = if (unchecked > 0) "${HealthText.count(unchecked, "login was", "logins were")} added or changed since then; check again to include them." else ""
            if ((at + changed).isNotEmpty()) Text(at + changed, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
        Box(Modifier.size(1.dp).semantics { liveRegion = LiveRegionMode.Polite; contentDescription = announcement })
    }
}

/** Nothing to fix in a section. */
@Composable
private fun AllClear(title: String, text: String) {
    Row(
        Modifier.fillMaxWidth().semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.m),
    ) {
        Icon(Icons.Outlined.CheckCircle, null, tint = PassAuthTheme.colors.ok)
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** One login: name, user name and site, its vault (shared vaults marked); opens its editor or its page. */
@Composable
private fun HealthRow(ctx: UiCtx, v: VaultData, e: Entry, first: Boolean, last: Boolean, trail: String?) {
    val i = e.item
    val vault = v.vaults.firstOrNull { it.id == e.vaultId }
    val canEdit = vault != null && vault.role != VaultRole.Read
    val shared = vault != null && !vault.personal
    val host = i.siteHost
    val name = i.name.ifEmpty { "Untitled" }
    val details = listOf(i.login?.username.orEmpty(), host).filter { it.isNotEmpty() }.joinToString(" · ")
    val place = (vault?.name ?: "Vault") + (if (shared) " (shared)" else "") + (if (canEdit) "" else ", view only")
    // Large text: lines wrap.
    val roomy = LocalDensity.current.fontScale < 1.3f
    val lines = if (roomy) 1 else Int.MAX_VALUE
    Row(
        Modifier.fillMaxWidth()
            .padding(top = if (first) Space.s else 0.dp)
            .cardSegment(first, last, MaterialTheme.colorScheme.surfaceContainer, PassAuthTheme.colors.line, dividerInset = Space.l + 40.dp + Space.m)
            .clickable(onClickLabel = if (canEdit) "Change password" else "Open") {
                ctx.go(if (canEdit) Route.Edit(e.id, fromHealth = true) else Route.ItemView(e.id, fromHealth = true))
            }
            .heightIn(min = 64.dp)
            .padding(start = Space.l, end = Space.s, top = Space.s, bottom = Space.s)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
    ) {
        SiteIcon(host, name, ctx.state.server, ctx.state.showSiteIcons, ctx.graph.icons, 40.dp)
        Column(Modifier.weight(1f).padding(start = Space.m, end = Space.xs)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = lines, overflow = TextOverflow.Ellipsis)
            if (details.isNotEmpty()) {
                Text(details, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = lines, overflow = TextOverflow.Ellipsis)
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.xs)) {
                if (shared) Icon(Icons.Outlined.Group, null, Modifier.size(14.dp), tint = PassAuthTheme.colors.muted)
                Text(place, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, maxLines = lines, overflow = TextOverflow.Ellipsis)
            }
            // Under the name (a narrow screen has no room for a column of its own).
            if (trail != null) Text(trail, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.error)
        }
        Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, null, tint = PassAuthTheme.colors.muted)
    }
}

/** No login has a password yet. */
@Composable
private fun EmptyHealth(ctx: UiCtx) {
    GroupCard(Modifier.padding(top = Space.l)) {
        Column(
            Modifier.fillMaxWidth().padding(Space.xl),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(Space.s),
        ) {
            Tile(icon = Icons.Outlined.Shield)
            Text(
                "No passwords to check yet", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center, modifier = Modifier.semantics { heading() },
            )
            Text(
                "When your logins have passwords, this page shows which ones are weak, reused or exposed in a data breach.",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center,
            )
            Spacer(Modifier.size(Space.xs))
            Button(onClick = { ctx.go(Route.New(ItemKind.Login)) }) {
                Icon(Icons.Outlined.Add, null)
                Spacer(Modifier.size(6.dp))
                Text("Add a login")
            }
            TextButton(onClick = { ctx.openUrl(ctx.state.server + "/import") }) { Text("Import from another app") }
        }
    }
}

/**
 * Quiet notes about a login's password on its page: weak, used by other logins (opens Password
 * health), found in a data breach (only after a breach check in this app session found it). Same
 * rules as Password health; [onChange] ("Change password") when the user can change the login.
 */
@Composable
fun PasswordNotes(ctx: UiCtx, v: VaultData, entry: Entry, onChange: (() -> Unit)?) {
    val health = ctx.graph.health
    val check by health.state.collectAsStateWithLifecycle()
    val password = passwordOf(entry)
    if (password.isEmpty()) return
    val weak = remember(password) { PasswordHealth.isWeak(password, ::estimateBits) }
    val others = remember(v.entries) { health.report(v) }.reuseCount[entry.id] ?: 0
    val breached = (check.results?.get(password) ?: 0) > 0
    if (!weak && others == 0 && !breached) return
    val warn = PassAuthTheme.colors.warn
    Column(Modifier.fillMaxWidth().padding(bottom = Space.s), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        if (weak) Note("Weak password", warn)
        if (others > 0) Note(HealthText.usedIn(others), warn) { ctx.go(Route.Settings(HEALTH)) }
        if (breached) Note("Found in a data breach", MaterialTheme.colorScheme.error)
        if (onChange != null) {
            TextButton(onClick = onChange, contentPadding = PaddingValues(horizontal = 0.dp, vertical = Space.s)) { Text("Change password") }
        }
    }
}

@Composable
private fun Note(text: String, color: Color, onClick: (() -> Unit)? = null) {
    val action = if (onClick != null) {
        Modifier.heightIn(min = 48.dp).clickable(role = Role.Button, onClickLabel = "Open password health", onClick = onClick)
    } else {
        Modifier
    }
    Row(action.semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Outlined.Shield, null, Modifier.size(16.dp), tint = color)
        Spacer(Modifier.size(6.dp))
        Text(
            text, style = MaterialTheme.typography.bodySmall, color = color,
            textDecoration = if (onClick != null) TextDecoration.Underline else null,
        )
    }
}
