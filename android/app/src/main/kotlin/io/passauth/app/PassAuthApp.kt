package io.passauth.app

import android.app.Application
import androidx.lifecycle.ProcessLifecycleOwner
import io.passauth.app.data.ApiClient
import io.passauth.app.data.ClipboardHelper
import io.passauth.app.data.IconLoader
import io.passauth.app.data.LockManager
import io.passauth.app.data.SecureStore
import io.passauth.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** App-wide singletons (manual dependency injection). */
class AppGraph(app: Application) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    val store = SecureStore(app, CoroutineScope(SupervisorJob() + Dispatchers.IO))
    val api = ApiClient(store)
    val repo = VaultRepository(store, api, scope)
    val lock = LockManager(repo, scope)
    val clipboard = ClipboardHelper(app, scope) { repo.state.value.settings.clearClipboard }
    val icons = IconLoader(api.http)
}

class PassAuthApp : Application() {
    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = AppGraph(this)
        ProcessLifecycleOwner.get().lifecycle.addObserver(graph.lock)
        // Vault timeout "never": stay unlocked across app restarts.
        graph.scope.launch { runCatching { graph.repo.restorePersisted() } }
    }
}
