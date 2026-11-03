package io.passauth.app.ui.permissions

import androidx.biometric.BiometricManager

/*
 * What the app may ask for, and how each one's state is shown. Pure logic (unit-tested).
 *
 * Only what PassAuth really uses (Play rejects unused permissions): the camera (QR codes),
 * the autofill service, the Credential Manager provider and fingerprint / face unlock.
 * No notifications, location or contacts. Android 17's local network permission
 * (ACCESS_LOCAL_NETWORK, for self-hosted servers on a home network) is enforced only for
 * apps targeting SDK 37+; with targetSdk 36 the INTERNET permission still grants it, so
 * it isn't listed. Add it here when targetSdk moves to 37.
 */
enum class Feature { Camera, Autofill, Passkeys, Biometrics }

enum class Access {
    /** Granted / turned on. */
    On,
    /** Can be asked (again). */
    Off,
    /** Runtime permission never requested. */
    NotAsked,
    /** Runtime permission denied for good: only Android's app settings can change it. */
    Blocked,
    /** Fingerprint / face unlock chosen on the first-launch screen; confirmed after sign-in. */
    Chosen,
    /** Biometric hardware present, nothing enrolled. */
    NotSetUp,
    /** Not on this phone. */
    Unavailable,
}

/** What the row's trailing control does. */
enum class Action { Request, OpenAppSettings, OpenSystemScreen, Enroll, Choose, None }

object PermissionModel {
    /**
     * A runtime permission. Android answers "should show rationale" = false both before
     * the first request and after a permanent denial, so [asked] tells them apart.
     */
    fun runtime(granted: Boolean, asked: Boolean, rationale: Boolean): Access = when {
        granted -> Access.On
        rationale -> Access.Off
        asked -> Access.Blocked
        else -> Access.NotAsked
    }

    fun service(enabled: Boolean): Access = if (enabled) Access.On else Access.Off

    /**
     * Fingerprint / face unlock from [BiometricManager.canAuthenticate] (strong biometrics).
     * [enabled]: on for the active account (Settings); null on the first-launch screen,
     * where [chosen] means it will be offered after sign-in.
     */
    fun biometrics(code: Int, enabled: Boolean?, chosen: Boolean): Access = when {
        enabled == true -> Access.On
        code == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Access.NotSetUp
        code != BiometricManager.BIOMETRIC_SUCCESS -> Access.Unavailable
        enabled == null && chosen -> Access.Chosen
        else -> Access.Off
    }

    fun action(feature: Feature, access: Access, intro: Boolean): Action = when (access) {
        Access.On, Access.Chosen, Access.Unavailable -> Action.None
        Access.Blocked -> Action.OpenAppSettings
        Access.NotSetUp -> Action.Enroll
        Access.Off, Access.NotAsked -> when (feature) {
            Feature.Camera -> Action.Request
            Feature.Autofill, Feature.Passkeys -> Action.OpenSystemScreen
            // First launch: nobody is signed in yet, so remember the choice.
            Feature.Biometrics -> if (intro) Action.Choose else Action.Request
        }
    }

    fun actionLabel(feature: Feature, access: Access): String? = when (access) {
        Access.Blocked -> "Open settings"
        Access.NotSetUp -> "Set up"
        Access.Off, Access.NotAsked -> if (feature == Feature.Camera) "Allow" else "Turn on"
        else -> null
    }

    /** Label next to the checkmark once done. */
    fun doneLabel(feature: Feature): String = if (feature == Feature.Camera) "Allowed" else "On"

    fun status(feature: Feature, access: Access): String = when (access) {
        Access.On -> if (feature == Feature.Camera) "Allowed" else "On"
        Access.Off -> if (feature == Feature.Camera) "Not allowed" else "Off"
        Access.NotAsked -> "Not asked"
        Access.Blocked -> "Not allowed. Change it in Android settings."
        Access.Chosen -> "Turns on after you sign in"
        Access.NotSetUp -> "No fingerprint or face set up on this phone"
        Access.Unavailable -> "Not available on this phone"
    }

    fun title(feature: Feature) = when (feature) {
        Feature.Camera -> "Camera"
        Feature.Autofill -> "Autofill service"
        Feature.Passkeys -> "Passkeys and passwords"
        Feature.Biometrics -> "Fingerprint or face unlock"
    }

    fun reason(feature: Feature) = when (feature) {
        Feature.Camera -> "Scan two-step login QR codes. Pictures are never kept."
        Feature.Autofill -> "Fill and save logins in apps and browsers."
        Feature.Passkeys -> "Sign in with passkeys and saved passwords through Android."
        Feature.Biometrics -> "Unlock your vault without typing your master password."
    }
}
