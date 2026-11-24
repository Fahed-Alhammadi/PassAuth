package io.passauth.app.ui.permissions

import io.passauth.app.data.Keystore
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.authenticate
import io.passauth.app.ui.biometricsAvailable

// There is no first-launch permissions screen (removed with the iOS App Review 5.1.1(iv) fix,
// 2026-11-24): every permission is asked by Android only when its feature is used: camera from
// "Scan QR code", notifications, autofill, passkeys and biometric unlock from their Settings rows.

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
