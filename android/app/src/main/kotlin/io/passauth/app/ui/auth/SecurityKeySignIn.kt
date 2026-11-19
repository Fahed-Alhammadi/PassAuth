package io.passauth.app.ui.auth

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.core.net.toUri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.passauth.app.data.SecurityKeyHandoff
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.theme.PassAuthTheme
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/**
 * Two-step login with a security key or passkey: the server's key page in the browser does the
 * WebAuthn ceremony and returns the assertion ([SecurityKeyHandoff]). [token] never leaves the app.
 * Cancelled or closed: no error, back to the choice. A failed finish shows the server's error
 * through [onError]; success moves the app on (signed in).
 */
@Composable
internal fun SecurityKeyPanel(ctx: UiCtx, token: String, rememberDevice: Boolean, onError: (String?) -> Unit) {
    val waiter = SecurityKeyHandoff.waiter
    var pending by remember { mutableStateOf<SecurityKeyHandoff.Waiter.Pending?>(null) }
    var busy by remember { mutableStateOf(false) }

    // Browsers with Auth Tab hand the callback back here; others go through TwoStepKeyActivity.
    val authTab = rememberLauncherForActivityResult(AuthTabIntent.AuthenticateUserResultContract()) { result ->
        val delivered = result.resultCode == AuthTabIntent.RESULT_OK && waiter.deliver(result.resultUri?.toString())
        // Closed, or returned something that isn't for this sign-in: the tab is gone, so stop waiting.
        if (!delivered) pending?.let(waiter::cancel)
    }
    // Leaving the screen (Back, another sign-in) ends the wait.
    DisposableEffect(Unit) { onDispose { pending?.let(waiter::cancel) } }

    fun use() {
        if (busy) return
        busy = true
        onError(null)
        ctx.scope.launch {
            try {
                val start = ctx.repo.startSecurityKey(token)
                val request = SecurityKeyHandoff.request(start.options, start.keyPage, start.server)
                if (request == null) {
                    onError(SecurityKeyHandoff.MISMATCH)
                    return@launch
                }
                val p = waiter.begin(request.challenge, request.state)
                pending = p
                if (!openKeyPage(ctx.activity, request.url, authTab)) {
                    waiter.cancel(p)
                    onError(SecurityKeyHandoff.NO_BROWSER)
                    return@launch
                }
                val result = p.await()
                pending = null
                if (result is SecurityKeyHandoff.Callback.Credential) ctx.repo.finishSecurityKey(token, result.json, rememberDevice)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                onError(errorMessage(e))
            } finally {
                pending = null
                busy = false
            }
        }
    }

    Text(SecurityKeyHandoff.EXPLAIN, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.fillMaxWidth())
    val waiting = pending
    if (waiting != null) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
        ) {
            CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
            Text(SecurityKeyHandoff.WAITING, style = MaterialTheme.typography.bodyMedium)
        }
        Text(SecurityKeyHandoff.NEVER_ASKS, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted, modifier = Modifier.fillMaxWidth())
        OutlinedButton(onClick = { waiter.cancel(waiting) }, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
    } else {
        PrimaryButton(if (busy) "Signing in…" else SecurityKeyHandoff.BUTTON, ::use, busy = busy)
    }
}

/**
 * Open the key page [url]: in an Auth Tab when the default Custom Tabs browser has one (the result
 * comes back to [authTab]), else in a Custom Tab or the browser (the page returns through
 * `TwoStepKeyActivity`). False when no browser can open it.
 */
private fun openKeyPage(activity: Activity, url: String, authTab: ActivityResultLauncher<Intent>): Boolean {
    val uri = url.toUri()
    val browser = runCatching { CustomTabsClient.getPackageName(activity, emptyList()) }.getOrNull()
    return try {
        if (browser != null && CustomTabsClient.isAuthTabSupported(activity, browser)) {
            val intent = AuthTabIntent.Builder().build()
            intent.intent.setPackage(browser)
            intent.launch(authTab, uri, SecurityKeyHandoff.SCHEME)
        } else if (browser != null) {
            val tab = CustomTabsIntent.Builder().setShowTitle(true).build()
            tab.intent.setPackage(browser)
            tab.launchUrl(activity, uri)
        } else {
            activity.startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
        }
        true
    } catch (_: ActivityNotFoundException) {
        false
    }
}
