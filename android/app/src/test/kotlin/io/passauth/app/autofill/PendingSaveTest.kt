package io.passauth.app.autofill

import io.passauth.app.autofill.AutofillEngine.Companion.PendingSave
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** Typed logins that wait for PassAuth's sheet or an unlock: taken once, and out of memory on every way out. */
class PendingSaveTest {
    private val app = FillTarget.App("com.example.app")
    private fun pending(at: Long = System.currentTimeMillis()) = PendingSave(app, "alex", "pw", "Example", at, accountId = "a1")

    @Before
    fun empty() = AutofillEngine.clearPendingSaves()

    @Test
    fun takenOnce() {
        val token = AutofillEngine.putPendingSave(pending())
        assertEquals("alex", AutofillEngine.takePendingSave(token)?.username)
        assertNull(AutofillEngine.takePendingSave(token))
        assertNull(AutofillEngine.takeUnclaimedSave(token))
        assertEquals(0, AutofillEngine.pendingCount())
    }

    @Test
    fun aSaveTheSheetNeverOpenedForIsTakenByTheFallback() {
        val token = AutofillEngine.putPendingSave(pending())
        assertEquals("a1", AutofillEngine.takeUnclaimedSave(token)?.accountId)
        assertNull(AutofillEngine.takeUnclaimedSave(token))
        assertNull(AutofillEngine.takePendingSave(token))
        assertEquals(0, AutofillEngine.pendingCount())
    }

    @Test
    fun aSaveTheSheetTookOverIsLeftToIt() {
        val token = AutofillEngine.putPendingSave(pending())
        AutofillEngine.claimPendingSave(token)
        // Not saved behind the sheet's back (the user may still cancel there)...
        assertNull(AutofillEngine.takeUnclaimedSave(token))
        assertEquals(1, AutofillEngine.pendingCount())
        // ...and still there for the sheet.
        assertEquals("pw", AutofillEngine.takePendingSave(token)?.password)
        assertEquals(0, AutofillEngine.pendingCount())
    }

    @Test
    fun closingTheSheetForgetsTheLogin() {
        val token = AutofillEngine.putPendingSave(pending())
        AutofillEngine.claimPendingSave(token)
        AutofillEngine.dropPendingSave(token)
        assertEquals(0, AutofillEngine.pendingCount())
        assertNull(AutofillEngine.takePendingSave(token))
    }

    @Test
    fun expiredSavesGoOnAnyAccess() {
        val old = System.currentTimeMillis() - 301_000
        val stale = AutofillEngine.putPendingSave(pending(old))
        // Reading another token is enough: nothing expired stays until the next save comes in.
        assertNull(AutofillEngine.takePendingSave("no such token"))
        assertEquals(0, AutofillEngine.pendingCount())
        assertNull(AutofillEngine.takePendingSave(stale))
        assertNull(AutofillEngine.takeUnclaimedSave(AutofillEngine.putPendingSave(pending(old))))
        AutofillEngine.putPendingSave(pending(old))
        AutofillEngine.claimPendingSave("no such token")
        assertEquals(0, AutofillEngine.pendingCount())
    }

    @Test
    fun lockLogoutAndAccountSwitchClearEverything() {
        val a = AutofillEngine.putPendingSave(pending())
        val b = AutofillEngine.putPendingSave(pending())
        AutofillEngine.claimPendingSave(b)
        AutofillEngine.clearPendingSaves()
        assertEquals(0, AutofillEngine.pendingCount())
        assertNull(AutofillEngine.takeUnclaimedSave(a))
        assertNull(AutofillEngine.takePendingSave(b))
    }
}
