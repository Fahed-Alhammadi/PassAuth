package io.passauth.app

import android.app.Application
import androidx.lifecycle.ProcessLifecycleOwner
import io.passauth.app.credentials.AssetLinksVerifier
import io.passauth.app.data.ApiClient
import io.passauth.app.data.ClipboardHelper
import io.passauth.app.data.IconLoader
import io.passauth.app.data.LiveSync
import io.passauth.app.data.LockManager
import io.passauth.app.data.SecureStore
import io.passauth.app.data.Status
import io.passauth.app.data.VaultData
import io.passauth.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** App-wide singletons (manual dependency injection). */
class AppGraph(app: Application) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    val store = SecureStore(app, CoroutineScope(SupervisorJob() + Dispatchers.IO))
    val api = ApiClient(store)
    val repo = VaultRepository(store, api, scope)
    val lock = LockManager(repo, scope)
    val clipboard = ClipboardHelper(app, scope) { repo.state.value.settings.clearClipboard }
    val icons = IconLoader(api.http)
    val live = LiveSync(repo, store, api.http)

    /** Digital Asset Links checks for apps (passkeys, WebViews). Debug builds can point it at a local test server. */
    val assetLinks = AssetLinksVerifier(api.http).let { default ->
        val base = BuildConfig.ASSET_LINKS_TEST_BASE
        if (base.isEmpty()) default else AssetLinksVerifier(api.http) { "$base/$it/.well-known/assetlinks.json" }
    }

    /** Restoring a "never" vault-timeout session after the process starts (the services wait for it). */
    var restoreJob: Job? = null

    /** App state once the encrypted store has been read (the services may have just started the process). */
    suspend fun loadedState(): io.passauth.app.data.AppState =
        withTimeoutOrNull(3_000) { repo.state.first { it.loaded } } ?: repo.state.value

    /**
     * The active account's unlocked vault, for the autofill and credential services
     * (which may start the process): waits briefly for the persisted session and the
     * first sync. Null if the account is locked or signed out.
     */
    suspend fun awaitVault(): VaultData? {
        withTimeoutOrNull(3_000) { restoreJob?.join() }
        val state = withTimeoutOrNull(3_000) { repo.state.first { it.loaded } } ?: return null
        if (state.status != Status.Unlocked) return null
        return repo.vault.value ?: withTimeoutOrNull(5_000) { repo.vault.filterNotNull().first() }
    }
}

class PassAuthApp : Application() {
    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = AppGraph(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(graph.lock)
        // Vault timeout "never": stay unlocked across app restarts.
        graph.restoreJob = graph.scope.launch { runCatching { graph.repo.restorePersisted() } }
    }
}

val android.content.Context.graph: AppGraph get() = (applicationContext as PassAuthApp).graph
