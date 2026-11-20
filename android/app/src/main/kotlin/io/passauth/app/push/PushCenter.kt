package io.passauth.app.push

import android.Manifest
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import io.passauth.app.BuildConfig
import io.passauth.app.MainActivity
import io.passauth.app.R
import io.passauth.app.data.Status
import io.passauth.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.resume

/**
 * The app's side of sign-in request notifications: Firebase (set up by hand from BuildConfig, no
 * analytics), the FCM token, registration with the servers, the notification and taps. One for the
 * process ([io.passauth.app.AppGraph]); [start] runs in `Application.onCreate`, before
 * [PassAuthMessagingService] can be created.
 */
class PushCenter(private val app: Application, private val repo: VaultRepository, private val scope: CoroutineScope) : DefaultLifecycleObserver {
    private val _available = MutableStateFlow(false)

    /** Notifications can work on this phone: Firebase is set up in this build and Google Play services are present. */
    val available: StateFlow<Boolean> = _available.asStateFlow()

    private val _granted = MutableStateFlow(false)

    /** Android lets PassAuth post notifications (re-read on start, resume and after asking). */
    val granted: StateFlow<Boolean> = _granted.asStateFlow()

    private val _signInRequests = MutableStateFlow(0)

    /**
     * Bumped when a sign-in request notification was tapped (or arrived while PassAuth runs):
     * the app asks for the open requests again (after unlock when locked).
     */
    val signInRequests: StateFlow<Int> = _signInRequests.asStateFlow()

    @Volatile private var token: String? = null

    private val registrar = PushRegistrar(
        send = { id, method, body -> repo.pushCall(id, method, body) },
        features = { id -> repo.featuresNow(id) },
    )

    fun start() {
        _available.value = setUpFirebase()
        refreshPermission()
        if (!_available.value) return
        createChannel()
        repo.beforeSignOut = { ids -> unregister(ids) }
        // The switch turned on, a sign-in or a log out: register with the servers that still need it.
        scope.launch {
            repo.state.filter { it.loaded }
                .map { s -> s.settings.signInNotifications to s.accounts.filter { a -> a.status == Status.Locked || a.status == Status.Unlocked }.map { it.id }.toSet() }
                .distinctUntilChanged()
                .collect { sync() }
        }
    }

    /** Firebase from this build's `google-services.json` client; false when it has none or the phone lacks Google Play services. */
    private fun setUpFirebase(): Boolean {
        if (!FirebaseSettings.configured) return false
        return try {
            if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(app) != ConnectionResult.SUCCESS) return false
            if (FirebaseApp.getApps(app).isEmpty()) {
                FirebaseApp.initializeApp(
                    app,
                    FirebaseOptions.Builder()
                        .setApplicationId(BuildConfig.FIREBASE_APP_ID)
                        .setApiKey(BuildConfig.FIREBASE_API_KEY)
                        .setProjectId(BuildConfig.FIREBASE_PROJECT_ID)
                        .setGcmSenderId(BuildConfig.FIREBASE_SENDER_ID)
                        .build(),
                )
            }
            FirebaseApp.getInstance().setDataCollectionDefaultEnabled(false)
            true
        } catch (e: Exception) {
            Log.w("PassAuth", "Notifications are unavailable: Firebase could not be set up", e)
            false
        }
    }

    /** Back on screen: Android's notification switch may have changed; register again if needed. */
    override fun onStart(owner: LifecycleOwner) {
        refreshPermission()
        scope.launch { sync() }
    }

    fun refreshPermission() {
        _granted.value = ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED &&
            NotificationManagerCompat.from(app).areNotificationsEnabled()
    }

    private val enabled: Boolean get() = repo.state.value.settings.signInNotifications

    /** Register with every signed-in account's server that offers push (start, sign-in, new token, switch on). */
    suspend fun sync() = syncing.withLock {
        if (!PushRules.active(_available.value, enabled, _granted.value)) return@withLock
        val messaging = FirebaseMessaging.getInstance()
        // Firebase keeps the token fresh (onNewToken) only while this is on; off by default (manifest).
        messaging.isAutoInitEnabled = true
        val t = token ?: fetchToken(messaging)?.also { token = it }
        registrar.sync(t, repo.signedInAccountIds())
    }

    /** One pass at a time (start, resume and the state watcher can ask together). */
    private val syncing = Mutex()

    private suspend fun fetchToken(messaging: FirebaseMessaging): String? = suspendCancellableCoroutine { c ->
        try {
            messaging.token.addOnCompleteListener { t -> if (c.isActive) c.resume(if (t.isSuccessful) t.result else null) }
        } catch (_: Exception) {
            c.resume(null)
        }
    }

    /** FCM gave this app a new token: every account registers it again. */
    fun newToken(t: String) {
        token = t
        scope.launch { sync() }
    }

    /** Switched off in Settings: every server forgets this phone's token. */
    suspend fun disable() {
        if (!_available.value) return
        runCatching { FirebaseMessaging.getInstance().isAutoInitEnabled = false }
        unregister(repo.signedInAccountIds())
    }

    /** Before signing accounts out: their servers forget this phone's token (best effort, 3 s at most). */
    suspend fun unregister(ids: List<String>) {
        if (token == null) ids.forEach(registrar::forget) else registrar.unregister(ids)
    }

    /** A message from the relay: post the notification and, if PassAuth is open, ask for the requests. */
    fun received(data: Map<String, String>) {
        val content = PushNotice.forMessage(data) ?: return
        _signInRequests.update { it + 1 }
        post(content)
    }

    /** The notification was tapped (MainActivity): ask for the open requests once the vault is open. */
    fun tapped() {
        NotificationManagerCompat.from(app).cancel(PushNotice.NOTIFICATION_ID)
        _signInRequests.update { it + 1 }
    }

    private fun createChannel() {
        val channel = NotificationChannel(PushNotice.CHANNEL_ID, PushNotice.CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH)
            .apply { description = PushNotice.CHANNEL_DESCRIPTION }
        app.getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun post(content: PushNotice.Content) {
        if (ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        createChannel()
        val open = PendingIntent.getActivity(
            app, 0, openIntent(app),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(app, content.channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(0xFF0866ED.toInt())
            .setContentTitle(content.title)
            .setContentText(content.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content.body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            // Fixed words, no account data: fine on the lock screen.
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(app).notify(PushNotice.NOTIFICATION_ID, n)
        } catch (_: SecurityException) {
            // Permission taken away meanwhile.
        }
    }

    companion object {
        /** Opens PassAuth's main screen and marks the sign-in request check. */
        fun openIntent(context: Context): Intent = Intent(context, MainActivity::class.java)
            .setAction(PushNotice.EXTRA_SIGN_IN_REQUEST)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(PushNotice.EXTRA_SIGN_IN_REQUEST, true)
    }
}

/** This build's Firebase client ([FirebaseClientConfig] in buildSrc, from `google-services.json`). */
object FirebaseSettings {
    val configured: Boolean
        get() = listOf(BuildConfig.FIREBASE_APP_ID, BuildConfig.FIREBASE_API_KEY, BuildConfig.FIREBASE_PROJECT_ID, BuildConfig.FIREBASE_SENDER_ID).all { it.isNotEmpty() }
}
