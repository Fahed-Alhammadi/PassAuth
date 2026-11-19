package io.passauth.app.ui

import io.passauth.app.data.UserException
import io.passauth.app.ui.auth.connectServer
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Final fixes L4: "Change server" on the sign-in screen closes once the new server is connected
 * (the screen's `onConnected`), and only then: a failed connect keeps it open with the reason.
 */
class ConnectServerTest {
    @Test
    fun aSuccessfulConnectClosesChangeServerAndAFailedOneDoesNot() = runBlocking {
        var closed = 0
        val asked = mutableListOf<String>()
        assertNull(connectServer("https://vault.example.com", { asked += it }, { closed++ }))
        assertEquals(listOf("https://vault.example.com"), asked)
        assertEquals(1, closed)

        val error = connectServer("https://nothing.example.com", { throw UserException("No PassAuth server answered at that address.") }, { closed++ })
        assertEquals("No PassAuth server answered at that address.", error)
        assertEquals("still open", 1, closed)

        // First setup (no sheet to close): nothing to call.
        assertNull(connectServer("https://vault.example.com", {}, null))
    }
}
