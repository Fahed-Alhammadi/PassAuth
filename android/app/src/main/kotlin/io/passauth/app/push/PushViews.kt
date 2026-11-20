package io.passauth.app.push

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.ToggleRow
import io.passauth.app.ui.permissions.Access
import io.passauth.app.ui.permissions.PermissionModel
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Radius
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.theme.TileColors

/** Android's notifications permission as a row state, and how to ask for it. */
class NotificationPermission(val access: Access, val request: () -> Unit)

/**
 * The notifications permission, re-read when PassAuth comes back on screen; [onAnswer] gets
 * Android's answer to [NotificationPermission.request] (true: allowed).
 */
@Composable
fun rememberNotificationPermission(ctx: UiCtx, onAnswer: (Boolean) -> Unit = {}): NotificationPermission {
    val push = ctx.graph.push
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        push.refreshPermission()
        resumes++
        onPauseOrDispose { }
    }
    val granted by push.granted.collectAsState()
    val asked = ctx.state.onboarding.notificationsAsked
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        ctx.launch { ctx.repo.updateOnboarding { it.copy(notificationsAsked = true) } }
        push.refreshPermission()
        resumes++
        onAnswer(ok)
    }
    val access = remember(resumes, asked, granted) {
        PermissionModel.runtime(
            granted = granted,
            asked = asked,
            rationale = ActivityCompat.shouldShowRequestPermissionRationale(ctx.activity, Manifest.permission.POST_NOTIFICATIONS),
        )
    }
    return NotificationPermission(access) { launcher.launch(Manifest.permission.POST_NOTIFICATIONS) }
}

/** Allowed: switch them on (if off) and register with the servers now. */
private fun UiCtx.turnedOn() = launch {
    repo.updateSettings { it.copy(signInNotifications = true) }
    graph.push.sync()
    notify("Sign-in request notifications are on.")
}

/** Android's notification settings for PassAuth (the app's settings page if that fails). */
fun openNotificationSettings(context: Context) {
    runCatching {
        context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName))
    }.recoverCatching {
        context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)))
    }
}

/**
 * Vault list, once: "Get sign-in requests as notifications" with Turn on / dismiss, while Android
 * hasn't asked yet, notifications can work here and the account's server sends them.
 */
@Composable
fun PushOfferCard(ctx: UiCtx) {
    val push = ctx.graph.push
    val available by push.available.collectAsState()
    if (!available || ctx.state.pushOffered != true || ctx.state.onboarding.pushOfferDismissed) return
    val permission = rememberNotificationPermission(ctx) { ok -> if (ok) ctx.turnedOn() }
    if (!PushRules.showOffer(available, permission.access, ctx.state.onboarding.pushOfferDismissed, ctx.state.pushOffered == true)) return
    val dismiss = { ctx.launch { ctx.repo.updateOnboarding { it.copy(pushOfferDismissed = true) } }.let { } }
    Surface(
        shape = RoundedCornerShape(Radius.card),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, PassAuthTheme.colors.line),
        modifier = Modifier.fillMaxWidth().padding(top = Space.s),
    ) {
        Row(Modifier.padding(start = Space.l, top = Space.m, bottom = Space.s), verticalAlignment = Alignment.Top) {
            Box(Modifier.padding(top = 2.dp).size(30.dp).background(TileColors.Red, RoundedCornerShape(7.dp)), contentAlignment = Alignment.Center) {
                Icon(Icons.Filled.NotificationsActive, null, Modifier.size(18.dp), tint = Color.White)
            }
            Column(Modifier.weight(1f).padding(start = Space.m), verticalArrangement = Arrangement.spacedBy(Space.xs)) {
                Text(
                    "Get sign-in requests as notifications",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.semantics { heading() },
                )
                Text(
                    "PassAuth tells you when a new device asks to sign in to your account, so you can approve it here. Notifications never show your email or server.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(Space.s), verticalAlignment = Alignment.CenterVertically) {
                    Button(onClick = permission.request, modifier = Modifier.heightIn(min = 48.dp)) { Text("Turn on") }
                    TextButton(onClick = dismiss, modifier = Modifier.heightIn(min = 48.dp)) { Text("Not now") }
                }
            }
            IconButton(onClick = dismiss) { Icon(Icons.Outlined.Close, contentDescription = "Dismiss", tint = PassAuthTheme.colors.muted) }
        }
    }
}

/**
 * Settings → Account security: "Sign-in request notifications". Shown where notifications can work
 * and the account's server sends them (or they're on, so they can be turned off).
 */
@Composable
fun PushSettingsRow(ctx: UiCtx) {
    val push = ctx.graph.push
    val available by push.available.collectAsState()
    if (!available) return
    val context = LocalContext.current
    val enabled = ctx.state.settings.signInNotifications
    val permission = rememberNotificationPermission(ctx) { ok -> if (ok) ctx.turnedOn() }
    val on = PushRules.switchOn(enabled, permission.access)
    if (ctx.state.pushOffered != true && !on) return
    ToggleRow(
        "Sign-in request notifications",
        on,
        { want ->
            when (PushRules.toggle(want, permission.access)) {
                PushRules.Toggle.Enable -> ctx.turnedOn()
                PushRules.Toggle.RequestPermission -> permission.request()
                PushRules.Toggle.OpenSettings -> openNotificationSettings(context)
                PushRules.Toggle.Disable -> ctx.launch {
                    ctx.repo.updateSettings { it.copy(signInNotifications = false) }
                    push.disable()
                    ctx.notify("Sign-in request notifications are off.")
                }
            }
        },
        help = when {
            on -> "PassAuth tells you when a new device asks to sign in to your account. Notifications never show your email or server."
            permission.access == Access.Blocked -> "Notifications are off for PassAuth in Android settings. Turn them on there to hear about sign-in requests from new devices."
            else -> "Get notified when a new device asks to sign in to your account, so you can approve it here. Notifications never show your email or server."
        },
    )
}
