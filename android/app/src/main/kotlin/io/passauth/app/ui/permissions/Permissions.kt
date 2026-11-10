package io.passauth.app.ui.permissions

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import io.passauth.app.data.Keystore
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.LogoMark
import io.passauth.app.ui.components.PromptHeader
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.authenticate
import io.passauth.app.ui.biometricsAvailable
import io.passauth.app.ui.settings.SystemServices
import io.passauth.app.ui.theme.PassAuthTheme

/**
 * First launch, before connecting to a server: what PassAuth may use, each one optional.
 * A decision page: brand bar, what is being decided, one card of choices, and the actions
 * pinned at the bottom.
 */
@Composable
fun PermissionsIntroScreen(ctx: UiCtx) {
    val finish = { ctx.launch { ctx.repo.updateOnboarding { it.copy(permissionsShown = true) } }.let { } }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).safeDrawingPadding(), horizontalAlignment = Alignment.CenterHorizontally) {
        Column(
            Modifier.widthIn(max = 560.dp).weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = Space.l),
            verticalArrangement = Arrangement.spacedBy(Space.l),
        ) {
            Row(Modifier.fillMaxWidth().heightIn(min = 56.dp), verticalAlignment = Alignment.CenterVertically) {
                LogoMark(26.dp)
                Spacer(Modifier.size(Space.s))
                Text("PassAuth", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            }
            PromptHeader("Set up PassAuth", "Choose what PassAuth may use on this phone.")
            GroupCard { Column(Modifier.padding(horizontal = Space.l, vertical = Space.xs)) { PermissionList(ctx, intro = true) } }
            PromptText("Everything is optional. You can change it later in Settings → Permissions.", Modifier.padding(horizontal = Space.xs))
        }
        Column(
            Modifier.widthIn(max = 560.dp).padding(start = Space.l, end = Space.l, top = Space.m, bottom = Space.s),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(Space.xs),
        ) {
            PrimaryButton("Continue", finish)
            QuietActions { QuietButton("Skip for now", finish) }
        }
    }
}

/** Settings → Permissions: the same list with each one's current state. */
@Composable
fun ColumnScope.PermissionsSettings(ctx: UiCtx) {
    PermissionList(ctx, intro = false)
    HorizontalDivider(color = PassAuthTheme.colors.line)
    Text(
        "PassAuth doesn't use your location, contacts or notifications.",
        style = MaterialTheme.typography.bodySmall,
        color = PassAuthTheme.colors.muted,
    )
}

@Composable
private fun PermissionList(ctx: UiCtx, intro: Boolean) {
    val context = LocalContext.current
    val activity = ctx.activity
    // Re-read everything when PassAuth comes back from Android's settings or a permission dialog.
    var resumes by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        resumes++
        onPauseOrDispose { }
    }
    val cameraAsked = ctx.state.onboarding.cameraAsked
    val requestCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        ctx.launch { ctx.repo.updateOnboarding { o -> o.copy(cameraAsked = true) } }
        resumes++
    }
    val camera = remember(resumes, cameraAsked) {
        PermissionModel.runtime(
            granted = ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
            asked = cameraAsked,
            rationale = ActivityCompat.shouldShowRequestPermissionRationale(activity, Manifest.permission.CAMERA),
        )
    }
    val autofillOn = remember(resumes) { SystemServices.autofillEnabled(context) }
    val providerOn = remember(resumes) { SystemServices.providerEnabled(context) }
    val biometricCode = remember(resumes) { BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) }
    val rows = listOf(
        Feature.Camera to camera,
        Feature.Autofill to PermissionModel.service(autofillOn),
        Feature.Passkeys to PermissionModel.service(providerOn),
        Feature.Biometrics to PermissionModel.biometrics(
            biometricCode,
            enabled = if (intro) null else ctx.state.biometricEnabled,
            chosen = ctx.state.onboarding.offerBiometric,
        ),
    )
    rows.forEachIndexed { n, (feature, access) ->
        // Inset to the text column (past the icon), like every list in the app.
        if (n > 0) HorizontalDivider(Modifier.padding(start = 24.dp + Space.m), color = PassAuthTheme.colors.line)
        PermissionRow(feature, access, intro) { action ->
            when (action) {
                Action.Request -> if (feature == Feature.Camera) requestCamera.launch(Manifest.permission.CAMERA) else ctx.turnOnBiometricUnlock()
                Action.OpenAppSettings -> openAppSettings(context)
                Action.OpenSystemScreen -> if (feature == Feature.Autofill) {
                    if (!SystemServices.openAutofillSettings(context)) ctx.notify("Open Android settings → Passwords, passkeys & accounts to choose PassAuth.")
                } else {
                    if (!SystemServices.openProviderSettings(context)) ctx.notify("Open Android settings → Passwords, passkeys & accounts to turn on PassAuth.")
                }
                Action.Enroll -> openBiometricEnroll(context)
                Action.Choose -> ctx.launch { ctx.repo.updateOnboarding { it.copy(offerBiometric = true) } }
                Action.None -> Unit
            }
        }
    }
}

private fun icon(feature: Feature): ImageVector = when (feature) {
    Feature.Camera -> Icons.Outlined.PhotoCamera
    Feature.Autofill -> Icons.Outlined.AutoFixHigh
    Feature.Passkeys -> Icons.Outlined.Key
    Feature.Biometrics -> Icons.Outlined.Fingerprint
}

@Composable
private fun PermissionRow(feature: Feature, access: Access, intro: Boolean, onAction: (Action) -> Unit) {
    val title = PermissionModel.title(feature)
    // "On" is already shown by the checkmark. On the first-launch screen everything starts
    // "not asked", so only the unusual states get a status line there.
    val showStatus = access != Access.On &&
        (!intro || access in setOf(Access.Blocked, Access.Chosen, Access.NotSetUp, Access.Unavailable))
    // Large fonts: the button goes under the text so neither gets squeezed.
    val stacked = LocalDensity.current.fontScale >= 1.5f
    val trailing: @Composable () -> Unit = {
        val label = PermissionModel.actionLabel(feature, access)
        val action = PermissionModel.action(feature, access, intro)
        when {
            // Quiet: the page's one filled button is "Continue".
            label != null && action != Action.None -> TextButton(
                onClick = { onAction(action) },
                modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = "$label: $title" },
            ) { Text(label) }
            access == Access.On || access == Access.Chosen -> Row(
                Modifier.heightIn(min = 40.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(Icons.Outlined.CheckCircle, null, tint = PassAuthTheme.colors.ok, modifier = Modifier.size(20.dp))
                Text(PermissionModel.doneLabel(feature), color = PassAuthTheme.colors.ok, style = MaterialTheme.typography.labelLarge)
            }
        }
    }
    Row(
        // Settings' card column already spaces its children.
        Modifier.fillMaxWidth().padding(vertical = if (intro) 12.dp else 2.dp),
        verticalAlignment = if (stacked) Alignment.Top else Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.m),
    ) {
        Icon(icon(feature), null, tint = MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // Title, reason and status are read as one ("Camera, Scan …, Not asked"), then the button.
            Column(Modifier.semantics(mergeDescendants = true) {}, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(PermissionModel.reason(feature), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (showStatus) {
                    Text(
                        PermissionModel.status(feature, access),
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        color = when (access) {
                            Access.On, Access.Chosen -> PassAuthTheme.colors.ok
                            Access.Blocked -> PassAuthTheme.colors.warn
                            else -> PassAuthTheme.colors.muted
                        },
                    )
                }
            }
            if (stacked) trailing()
        }
        if (!stacked) trailing()
    }
}

private fun openAppSettings(context: Context) {
    runCatching {
        context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)))
    }
}

/** Android's "add a fingerprint / face" flow (strong biometrics), or the security settings. */
private fun openBiometricEnroll(context: Context) {
    runCatching {
        context.startActivity(Intent(Settings.ACTION_BIOMETRIC_ENROLL).putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BIOMETRIC_STRONG))
    }.recoverCatching { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }
}

/** Turns on biometric unlock for the active (unlocked) account after one biometric confirmation. */
fun UiCtx.turnOnBiometricUnlock() {
    if (!biometricsAvailable(activity)) {
        notify("Set up a fingerprint or face unlock in Android settings first.")
        return
    }
    launch {
        val cipher = Keystore.biometricCipher(Keystore.newBiometricKey(state.activeId))
        val ok = activity.authenticate(cipher, "Turn on biometric unlock", state.email) ?: return@launch
        repo.enableBiometric(ok)
        notify("Biometric unlock is on.")
    }
}

/**
 * After the first sign-in or unlock: if fingerprint / face unlock was chosen on the
 * first-launch screen, offer it once for this account (one confirmation).
 */
@Composable
fun BiometricOffer(ctx: UiCtx) {
    val st = ctx.state
    if (!st.onboarding.offerBiometric) return
    val clear = { ctx.launch { ctx.repo.updateOnboarding { it.copy(offerBiometric = false) } }.let { } }
    if (st.biometricEnabled || !biometricsAvailable(ctx.activity)) {
        LaunchedEffect(Unit) { clear() }
        return
    }
    DecisionSheet(
        onDismiss = clear,
        title = "Turn on fingerprint or face unlock?",
        subtitle = st.email,
        tile = { Tile(icon = Icons.Outlined.Fingerprint) },
        actions = {
            PrimaryButton("Turn on", {
                clear()
                ctx.turnOnBiometricUnlock()
            })
            QuietActions { QuietButton("Not now", clear) }
        },
    ) { PromptText("You chose this when setting up PassAuth. Confirm once to unlock your vault without typing your master password.") }
}
