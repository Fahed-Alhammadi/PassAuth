package io.passauth.app

import androidx.biometric.BiometricManager
import io.passauth.app.data.AccountData
import io.passauth.app.data.AppJson
import io.passauth.app.data.Onboarding
import io.passauth.app.data.Stored
import io.passauth.app.ui.permissions.Access
import io.passauth.app.ui.permissions.Action
import io.passauth.app.ui.permissions.Feature
import io.passauth.app.ui.permissions.PermissionModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionsTest {
    @Test
    fun introShownOnceOnFirstLaunch() {
        assertTrue(Stored().showPermissionsIntro)
        // A record without a server (fresh install) still counts as first launch.
        assertTrue(Stored(accounts = mapOf("a" to AccountData())).showPermissionsIntro)
        assertFalse(Stored(onboarding = Onboarding(permissionsShown = true)).showPermissionsIntro)
        // Already using the app (upgrade): not shown, it's in Settings → Permissions.
        assertFalse(Stored(accounts = mapOf("a" to AccountData(server = "https://vault.example.com"))).showPermissionsIntro)
    }

    @Test
    fun onboardingSurvivesStorageAndOldFilesDefault() {
        val s = Stored(onboarding = Onboarding(permissionsShown = true, cameraAsked = true, offerBiometric = true))
        val back = AppJson.decodeFromString(Stored.serializer(), AppJson.encodeToString(Stored.serializer(), s))
        assertEquals(s.onboarding, back.onboarding)
        // Files written before this feature have no "onboarding".
        assertEquals(Onboarding(), AppJson.decodeFromString(Stored.serializer(), """{"deviceId":"d"}""").onboarding)
    }

    @Test
    fun runtimePermissionStates() {
        assertEquals(Access.On, PermissionModel.runtime(granted = true, asked = true, rationale = false))
        assertEquals(Access.NotAsked, PermissionModel.runtime(granted = false, asked = false, rationale = false))
        assertEquals(Access.Off, PermissionModel.runtime(granted = false, asked = true, rationale = true))
        // Denied once elsewhere (rationale) even if this screen never asked.
        assertEquals(Access.Off, PermissionModel.runtime(granted = false, asked = false, rationale = true))
        assertEquals(Access.Blocked, PermissionModel.runtime(granted = false, asked = true, rationale = false))
    }

    @Test
    fun biometricStates() {
        val ok = BiometricManager.BIOMETRIC_SUCCESS
        assertEquals(Access.Off, PermissionModel.biometrics(ok, enabled = null, chosen = false))
        assertEquals(Access.Chosen, PermissionModel.biometrics(ok, enabled = null, chosen = true))
        assertEquals(Access.Off, PermissionModel.biometrics(ok, enabled = false, chosen = true))
        assertEquals(Access.On, PermissionModel.biometrics(ok, enabled = true, chosen = false))
        assertEquals(Access.NotSetUp, PermissionModel.biometrics(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED, null, false))
        assertEquals(Access.Unavailable, PermissionModel.biometrics(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE, null, true))
    }

    @Test
    fun actionsAndLabels() {
        assertEquals(Action.Request, PermissionModel.action(Feature.Camera, Access.NotAsked, intro = true))
        assertEquals(Action.OpenAppSettings, PermissionModel.action(Feature.Camera, Access.Blocked, intro = false))
        assertEquals(Action.OpenSystemScreen, PermissionModel.action(Feature.Autofill, Access.Off, intro = true))
        assertEquals(Action.OpenSystemScreen, PermissionModel.action(Feature.Passkeys, Access.Off, intro = false))
        assertEquals(Action.Choose, PermissionModel.action(Feature.Biometrics, Access.Off, intro = true))
        assertEquals(Action.Request, PermissionModel.action(Feature.Biometrics, Access.Off, intro = false))
        assertEquals(Action.Enroll, PermissionModel.action(Feature.Biometrics, Access.NotSetUp, intro = true))
        assertEquals(Action.None, PermissionModel.action(Feature.Camera, Access.On, intro = true))

        assertEquals("Allow", PermissionModel.actionLabel(Feature.Camera, Access.NotAsked))
        assertEquals("Turn on", PermissionModel.actionLabel(Feature.Autofill, Access.Off))
        assertEquals("Open settings", PermissionModel.actionLabel(Feature.Camera, Access.Blocked))
        assertNull(PermissionModel.actionLabel(Feature.Camera, Access.On))
        assertEquals("Allowed", PermissionModel.doneLabel(Feature.Camera))
        assertEquals("On", PermissionModel.doneLabel(Feature.Passkeys))

        assertEquals("Allowed", PermissionModel.status(Feature.Camera, Access.On))
        assertEquals("Not allowed", PermissionModel.status(Feature.Camera, Access.Off))
        assertEquals("Not asked", PermissionModel.status(Feature.Camera, Access.NotAsked))
        assertEquals("Off", PermissionModel.status(Feature.Autofill, Access.Off))
    }
}
