package io.passauth.app.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.passauth.app.AppGraph
import io.passauth.app.MainActivity
import io.passauth.app.SecureActivity
import io.passauth.app.data.ApiException
import io.passauth.app.data.AppState
import io.passauth.app.data.ItemKind
import io.passauth.app.data.Status
import io.passauth.app.data.VaultRepository
import io.passauth.app.data.copiedNote
import io.passauth.app.ui.auth.LoginScreen
import io.passauth.app.ui.auth.SetupScreen
import io.passauth.app.ui.auth.UnlockScreen
import io.passauth.app.ui.settings.SettingsScreen
import io.passauth.app.ui.vault.EditScreen
import io.passauth.app.ui.vault.ItemScreen
import io.passauth.app.ui.vault.ListFilter
import io.passauth.app.ui.vault.VaultListScreen
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

sealed interface Route {
    data object Vault : Route
    data class ItemView(val id: String) : Route
    data class Edit(val id: String) : Route
    data class New(val kind: ItemKind) : Route
    data object Generator : Route
    data class Settings(val section: String? = null) : Route
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

fun errorMessage(e: Throwable): String {
    val m = e.message.orEmpty()
    return when {
        m == VaultRepository.SECRET_KEY_REQUIRED -> "This account uses a Secret Key. Enter it from your Emergency Kit."
        m == "email_not_verified" -> "Confirm your email address first, then sign in."
        e is ApiException && e.code == "invalid_credentials" -> "Wrong email, master password or Secret Key."
        e is ApiException && e.code == "rate_limited" -> "Too many attempts. Wait a moment and try again."
        e is io.passauth.core.CoreException.DecryptFailed -> "Wrong master password or Secret Key."
        e is io.passauth.core.CoreException -> "Something went wrong: $m"
        m.isEmpty() -> "Something went wrong."
        e is ApiException -> m.replaceFirstChar { it.uppercase() }.let { if (it.endsWith('.')) it else "$it." }
        else -> m
    }
}

/** Keeps the window secure (FLAG_SECURE) while this is in the composition. */
@Composable
fun SecureWindow() {
    val activity = LocalContext.current as? SecureActivity
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
    LaunchedEffect(state.status) { if (state.status != Status.Unlocked) route = Route.Vault }
    // Opened from Android's autofill / passkey settings: show Settings → Autofill once unlocked.
    val requested by activity.requestedRoute
    LaunchedEffect(requested, state.status) {
        val r = requested ?: return@LaunchedEffect
        if (state.status == Status.Unlocked) {
            route = r
            activity.requestedRoute.value = null
        }
    }
    // Light status bar icons over the navy header (unlocked screens) and in dark mode.
    val dark = io.passauth.app.ui.theme.isDark(state.settings.theme)
    androidx.compose.runtime.SideEffect {
        androidx.core.view.WindowCompat.getInsetsController(activity.window, activity.window.decorView).apply {
            isAppearanceLightStatusBars = !dark && state.status != Status.Unlocked
            isAppearanceLightNavigationBars = !dark
        }
    }

    Scaffold(
        snackbarHost = {
            // Item pages have their own footer (Edit, trash): keep notices above it.
            val aboveFooter = state.status == Status.Unlocked && route is Route.ItemView
            SnackbarHost(snackbar, Modifier.padding(bottom = if (aboveFooter) 72.dp else 0.dp))
        },
        bottomBar = {
            if (state.status == Status.Unlocked && (route is Route.Vault || route is Route.Generator || route is Route.Settings)) {
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
                when (state.status) {
                    Status.Setup -> SetupScreen(ctx)
                    Status.LoggedOut -> LoginScreen(ctx)
                    Status.Locked -> UnlockScreen(ctx)
                    Status.Unlocked -> {
                        SecureWindow()
                        Main(ctx, route) { route = it }
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
                is Route.Edit -> Route.ItemView(route.id)
                is Route.Settings -> if (route.section != null) Route.Settings() else Route.Vault
                else -> Route.Vault
            },
        )
    }
    LaunchedEffect(Unit) { runCatching { ctx.repo.refreshIfStale() } }
    when (route) {
        Route.Vault -> VaultListScreen(ctx, filter) { filter = it }
        is Route.ItemView -> ItemScreen(ctx, route.id)
        is Route.Edit -> EditScreen(ctx, id = route.id)
        is Route.New -> EditScreen(ctx, kind = route.kind)
        Route.Generator -> GeneratorScreen(ctx)
        is Route.Settings -> SettingsScreen(ctx, route.section)
    }
}

/** Saves the current route across configuration changes (rotation). */
private val RouteSaver = androidx.compose.runtime.saveable.Saver<Route, String>(
    save = { r ->
        when (r) {
            Route.Vault -> "vault"
            is Route.ItemView -> "item:${r.id}"
            is Route.Edit -> "edit:${r.id}"
            is Route.New -> "new:${r.kind.name}"
            Route.Generator -> "generator"
            is Route.Settings -> "settings:${r.section.orEmpty()}"
        }
    },
    restore = { v ->
        val (k, arg) = v.split(':', limit = 2).let { it[0] to it.getOrElse(1) { "" } }
        when (k) {
            "item" -> Route.ItemView(arg)
            "edit" -> Route.Edit(arg)
            "new" -> Route.New(ItemKind.valueOf(arg))
            "generator" -> Route.Generator
            "settings" -> Route.Settings(arg.ifEmpty { null })
            else -> Route.Vault
        }
    },
)
