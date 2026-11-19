package io.passauth.app.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.theme.PassAuthTheme

/**
 * Chrome fills through a separate autofill service only when "Autofill using another service" is
 * on in Chrome's own settings; Android's choice alone isn't enough. Shown only when Chrome is
 * installed (Settings → Autofill and the first-launch setup screen). [refresh]: re-read after
 * PassAuth comes back to the front.
 */
@Composable
fun ChromeAutofillHint(ctx: UiCtx, refresh: Int, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val chrome = remember(refresh) { SystemServices.chromePackage(context) } ?: return
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text("Chrome", style = MaterialTheme.typography.bodyLarge)
            Text(
                "Turn on Settings → Autofill services → Autofill using another service, so Chrome asks PassAuth.",
                style = MaterialTheme.typography.bodySmall,
                color = PassAuthTheme.colors.muted,
            )
        }
        TextButton(onClick = {
            if (!SystemServices.openChromeAutofillSettings(context, chrome)) ctx.notify("Open Chrome → Settings → Autofill services.")
        }, modifier = Modifier.heightIn(min = 48.dp)) { Text("Open Chrome") }
    }
}
