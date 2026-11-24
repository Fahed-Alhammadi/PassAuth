package io.passauth.app.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Casino
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.passauth.app.AppGraph
import io.passauth.app.MainActivity
import io.passauth.app.SecureActivity
import io.passauth.app.data.ApiException
import io.passauth.app.data.AppState
import io.passauth.app.data.DeviceApprovals
import io.passauth.app.data.DeviceLogin
import io.passauth.app.data.ServerErrors
import io.passauth.app.data.ShownText
import io.passauth.app.data.UserException
import io.passauth.core.CoreException
import io.passauth.app.data.ItemKind
import io.passauth.app.data.Status
import io.passauth.app.data.VaultRepository
import io.passauth.app.data.copiedNote
import io.passauth.app.ui.auth.LoginScreen
import io.passauth.app.ui.auth.SetupScreen
import io.passauth.app.ui.auth.UnlockScreen
import io.passauth.app.data.TwoStepGate
import io.passauth.app.ui.settings.InvitationsScreen
import io.passauth.app.ui.settings.SettingsScreen
import io.passauth.app.ui.settings.TwoStepRequiredScreen
import io.passauth.app.ui.vault.EditScreen
import io.passauth.app.ui.vault.ItemScreen
import io.passauth.app.ui.vault.ListFilter
import io.passauth.app.ui.vault.PasswordHistoryScreen
import io.passauth.app.ui.vault.VaultListScreen
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

sealed interface Route {
    data object Vault : Route

    /** [fromHealth]: opened from Settings → Password health, where Back (and Save) returns. */
    data class ItemView(val id: String, val fromHealth: Boolean = false) : Route
    data class Edit(val id: String, val fromHealth: Boolean = false) : Route
    data class History(val id: String, val fromHealth: Boolean = false) : Route
    data class New(val kind: ItemKind) : Route
    data object Generator : Route
    data class Settings(val section: String? = null) : Route

    /** Vault invitations; [fromVault]: opened from the vault list's notice, where Back returns. */
    data class Invitations(val fromVault: Boolean = false) : Route
}

/** What every screen gets: state, navigation, notices, copy. */
class UiCtx(
    val graph: AppGraph,
    val state: AppState,
    val activity: SecureActivity,
    val scope: CoroutineScope,
    val notify: (String) -> Unit,
    val go: (Route) -> Unit,
) {
    val repo: VaultRepository get() = graph.repo

    fun copy(text: String, label: String) {
        val after = graph.clipboard.copy(text, label)
        notify(copiedNote(label, after))
    }

    /** Run an action, showing its error as a notice. */
    fun launch(block: suspend () -> Unit): Job = scope.launch {
        try {
            block()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            notify(errorMessage(e))
        }
    }

    fun openUrl(url: String) {
        runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)) }
            .onFailure { notify("No app can open this address.") }
    }
}

/**
 * One wording for errors across the app. A server's answer always gets the app's own words
 * ([ServerErrors]: its text only as a labelled, cleaned and shortened detail of an error the app
 * doesn't know); the app's own errors ([UserException]) are shown as they are.
 */
fun errorMessage(e: Throwable): String {
    // The server's policies (400 secret_key_required / kdf_too_weak, 403 two_step_required).
    io.passauth.app.data.PolicyRules.errorMessage(e)?.let { return it }
    val m = e.message.orEmpty()
    return when {
        m == VaultRepository.SECRET_KEY_REQUIRED -> "This account uses a Secret Key. Enter it from your Emergency Kit."
        m == "email_not_verified" -> "Confirm your email address first, then sign in."
        e is ApiException -> ServerErrors.text(e)
        e is CoreException.DecryptFailed -> "Wrong master password or Secret Key."
        e is CoreException.WeakKdf -> "Your server asked for weaker encryption settings than PassAuth allows, so nothing was done. Ask your server's admin."
        e is CoreException.KdfTooStrong -> "Your server asked for stronger encryption settings than PassAuth supports, so nothing was done. Ask your server's admin."
        e is CoreException.PhraseMismatch -> DeviceApprovals.MISMATCH
        e is CoreException.WrongCode -> "That code doesn't match."
        e is CoreException.TooManyWrongCodes -> DeviceLogin.TOO_MANY_CODES
        e is CoreException.NotConfirmed -> DeviceLogin.CODE_PROMPT
        e is CoreException -> "Something went wrong: ${ShownText.clean(m, ServerErrors.MESSAGE_MAX)}"
        // Its message quotes the answer it couldn't read.
        e is kotlinx.serialization.SerializationException -> "Your PassAuth server sent an answer PassAuth couldn't read. Try again."
        m.isEmpty() -> "Something went wrong."
        e is UserException -> m
        else -> ShownText.clean(m, ServerErrors.MESSAGE_MAX)
    }
}

/** Keeps the window secure (FLAG_SECURE) while this is in the composition. */
@Composable
fun SecureWindow() {
    val activity = LocalActivity.current as? SecureActivity
    DisposableEffect(activity) {
        activity?.setSecure(true)
        onDispose { activity?.setSecure(false) }
    }
}

@Composable
fun AppRoot(graph: AppGraph, state: AppState, activity: MainActivity) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val notify: (String) -> Unit = remember {
        { text: String ->
            scope.launch {
                snackbar.currentSnackbarData?.dismiss()
                snackbar.showSnackbar(text)
            }.let { }
        }
    }
    var route by rememberSaveable(state.activeId, stateSaver = RouteSaver) { mutableStateOf<Route>(Route.Vault) }
    val ctx = UiCtx(graph, state, activity, scope, notify) { route = it }
    LaunchedEffect(state.status, state.twoStepRequired) { if (state.status != Status.Unlocked || state.twoStepRequired) route = Route.Vault }
    // Sign-in requests from new devices: asked for whenever the vault is open here (and by live sync).
    val vaultOpen = state.status == Status.Unlocked && !state.twoStepRequired
    // A sign-in request notification arrived or was tapped: ask again (once the vault is open).
    val pushed by graph.push.signInRequests.collectAsState()
    LaunchedEffect(state.activeId, vaultOpen, pushed) {
        if (!vaultOpen) return@LaunchedEffect graph.inbox.clear()
        try {
            graph.inbox.refresh()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Exception) {
            // Offline or the server said no: live sync asks again when it connects.
        }
    }
    // Opened from Android's autofill / passkey settings: show Settings → Autofill once unlocked.
    val requested by activity.requestedRoute
    LaunchedEffect(requested, state.status, state.twoStepRequired) {
        val r = requested ?: return@LaunchedEffect
        if (state.status == Status.Unlocked && !state.twoStepRequired) {
            route = r
            activity.requestedRoute.value = null
        }
    }
    // Dark status bar icons on the light page colour, light ones in dark mode.
    val dark = io.passauth.app.ui.theme.isDark(state.settings.theme)
    androidx.compose.runtime.SideEffect {
        androidx.core.view.WindowCompat.getInsetsController(activity.window, activity.window.decorView).apply {
            isAppearanceLightStatusBars = !dark
            isAppearanceLightNavigationBars = !dark
        }
    }

    Scaffold(
        snackbarHost = {
            // Item pages have their own footer (Edit, trash): keep notices above it.
            val aboveFooter = state.status == Status.Unlocked && !state.twoStepRequired && route is Route.ItemView
            SnackbarHost(snackbar, Modifier.padding(bottom = if (aboveFooter) 72.dp else 0.dp))
        },
        bottomBar = {
            if (state.status == Status.Unlocked && !state.twoStepRequired && (route is Route.Vault || route is Route.Generator || route is Route.Settings)) {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainer) {
                    // The selected tab uses the brand accent (#0866ED light, #3D8BFF dark), as in the extension.
                    val navColors = NavigationBarItemDefaults.colors(
                        selectedIconColor = MaterialTheme.colorScheme.primary,
                        selectedTextColor = MaterialTheme.colorScheme.primary,
                        indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                    )
                    NavigationBarItem(
                        selected = route is Route.Vault, onClick = { route = Route.Vault },
                        icon = { Icon(Icons.Outlined.Lock, null) }, label = { Text("Vault") }, colors = navColors,
                    )
                    NavigationBarItem(
                        selected = route is Route.Generator, onClick = { route = Route.Generator },
                        icon = { Icon(Icons.Outlined.Casino, null) }, label = { Text("Generator") }, colors = navColors,
                    )
                    NavigationBarItem(
                        selected = route is Route.Settings, onClick = { route = Route.Settings() },
                        icon = { Icon(Icons.Outlined.Settings, null) }, label = { Text("Settings") }, colors = navColors,
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(bottom = padding.calculateBottomPadding())) {
            if (!state.loaded) {
                CircularProgressIndicator(Modifier.align(Alignment.Center))
                return@Box
            }
            // Keyed by account so switching accounts starts each screen fresh.
            key(state.activeId) {
                when {
                    // The server requires two-step login first: only setting a method up, or signing out.
                    TwoStepGate.shows(state.status, state.twoStepRequired) -> TwoStepRequiredScreen(ctx)
                    state.status == Status.Setup -> SetupScreen(ctx)
                    state.status == Status.LoggedOut -> LoginScreen(ctx)
                    state.status == Status.Locked -> UnlockScreen(ctx)
                    else -> {
                        SecureWindow()
                        Main(ctx, route) { route = it }
                        AuthRequestPrompt(ctx)
                    }
                }
            }
        }
    }
}

@Composable
private fun Main(ctx: UiCtx, route: Route, go: (Route) -> Unit) {
    var filter by remember { mutableStateOf(ListFilter()) }
    BackHandler(enabled = route != Route.Vault) {
        go(
            when (route) {
                is Route.Edit -> if (route.fromHealth) Route.Settings(HEALTH) else Route.ItemView(route.id)
                is Route.History -> Route.ItemView(route.id, route.fromHealth)
                is Route.ItemView -> if (route.fromHealth) Route.Settings(HEALTH) else Route.Vault
                is Route.Settings -> when (route.section) {
                    null -> Route.Vault
                    "export" -> Route.Settings("vault")
                    "password", "two-step", "sessions" -> Route.Settings("security")
                    else -> Route.Settings()
                }
                is Route.Invitations -> if (route.fromVault) Route.Vault else Route.Settings()
                else -> Route.Vault
            },
        )
    }
    LaunchedEffect(Unit) { runCatching { ctx.repo.refreshIfStale() } }
    when (route) {
        Route.Vault -> VaultListScreen(ctx, filter) { filter = it }
        is Route.ItemView -> ItemScreen(ctx, route.id, route.fromHealth)
        is Route.Edit -> EditScreen(ctx, id = route.id, fromHealth = route.fromHealth)
        is Route.History -> PasswordHistoryScreen(ctx, route.id, route.fromHealth)
        is Route.New -> EditScreen(ctx, kind = route.kind)
        Route.Generator -> GeneratorScreen(ctx)
        is Route.Settings -> SettingsScreen(ctx, route.section)
        is Route.Invitations -> InvitationsScreen(ctx, route.fromVault)
    }
}

/** The Settings section of Password health. */
const val HEALTH = "health"

/** Saves the current route across configuration changes (rotation). */
private val RouteSaver = androidx.compose.runtime.saveable.Saver<Route, String>(
    save = { r ->
        when (r) {
            Route.Vault -> "vault"
            is Route.ItemView -> "${if (r.fromHealth) "h" else ""}item:${r.id}"
            is Route.Edit -> "${if (r.fromHealth) "h" else ""}edit:${r.id}"
            is Route.History -> "${if (r.fromHealth) "h" else ""}history:${r.id}"
            is Route.New -> "new:${r.kind.name}"
            Route.Generator -> "generator"
            is Route.Settings -> "settings:${r.section.orEmpty()}"
            is Route.Invitations -> "invitations:${if (r.fromVault) "vault" else ""}"
        }
    },
    restore = { v ->
        val (k, arg) = v.split(':', limit = 2).let { it[0] to it.getOrElse(1) { "" } }
        when (k) {
            "item" -> Route.ItemView(arg)
            "edit" -> Route.Edit(arg)
            "history" -> Route.History(arg)
            "hitem" -> Route.ItemView(arg, fromHealth = true)
            "hedit" -> Route.Edit(arg, fromHealth = true)
            "hhistory" -> Route.History(arg, fromHealth = true)
            "new" -> Route.New(ItemKind.valueOf(arg))
            "generator" -> Route.Generator
            "settings" -> Route.Settings(arg.ifEmpty { null })
            "invitations" -> Route.Invitations(fromVault = arg == "vault")
            else -> Route.Vault
        }
    },
)
