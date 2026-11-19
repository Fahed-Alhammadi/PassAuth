package io.passauth.app.ui.settings

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.credentials.CredentialManager
import io.passauth.app.credentials.PassAuthCredentialService

/** Status of, and Android's settings screens for, PassAuth's autofill service and credential provider. */
object SystemServices {
    fun autofillEnabled(context: Context): Boolean =
        runCatching { context.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true }.getOrDefault(false)

    fun providerEnabled(context: Context): Boolean = runCatching {
        context.getSystemService(android.credentials.CredentialManager::class.java)
            ?.isEnabledCredentialProviderService(ComponentName(context, PassAuthCredentialService::class.java)) == true
    }.getOrDefault(false)

    /**
     * Android's "choose autofill service" screen with PassAuth preselected. That screen
     * closes at once when PassAuth is already chosen, so then open "Passwords, passkeys
     * & accounts" (where the service can be changed) instead.
     */
    fun openAutofillSettings(context: Context): Boolean = runCatching {
        val intent = if (autofillEnabled(context)) {
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER)
        } else {
            Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:${context.packageName}"))
        }
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }.isSuccess

    /** Chrome's release channels, stable first. */
    private val CHROME = listOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary")

    /** The installed Chrome (stable first), or null. Chrome asks a separate autofill service only when told to in its own settings. */
    fun chromePackage(context: Context): String? = CHROME.firstOrNull { pkg ->
        runCatching { context.packageManager.getApplicationInfo(pkg, 0).enabled }.getOrDefault(false)
    }

    /**
     * Chrome's autofill settings (where "Autofill using another service" is), through the intent
     * Chrome documents for this; Chrome itself when that isn't there (older versions).
     */
    fun openChromeAutofillSettings(context: Context, pkg: String): Boolean = runCatching {
        context.startActivity(
            Intent(Intent.ACTION_APPLICATION_PREFERENCES)
                .addCategory(Intent.CATEGORY_DEFAULT)
                .addCategory(Intent.CATEGORY_APP_BROWSER)
                .addCategory(Intent.CATEGORY_PREFERENCE)
                .setPackage(pkg)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }.recoverCatching {
        context.startActivity(context.packageManager.getLaunchIntentForPackage(pkg)!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }.isSuccess

    /** Android's Credential Manager provider settings (or the Passwords & accounts screen). */
    fun openProviderSettings(context: Context): Boolean = runCatching {
        CredentialManager.create(context).createSettingsPendingIntent().send()
    }.recoverCatching {
        context.startActivity(
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }.isSuccess
}
