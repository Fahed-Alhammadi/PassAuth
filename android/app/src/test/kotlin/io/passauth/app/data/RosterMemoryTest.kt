package io.passauth.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Emergency roster memory lives per account (server + user id), outside the account records. */
class RosterMemoryTest {
    private val server = "https://pa.example"
    private fun bundle(userId: String) = """{"account_id":"$userId","kdf":{}}"""
    private val tokens = Tokens("access", "refresh")

    private fun signedInAs(userId: String, email: String = "$userId@example.com"): Stored =
        Stored(activeId = "r1", accounts = mapOf("r1" to AccountData(server = server))).signedIn("r1", email, tokens, bundle(userId), emptySet())

    @Test
    fun logOutAndSignInAgainKeepsTheVersion() {
        var s = signedInAs("u1").rememberingRoster(server, "u1", 7, "sealed-7")
        // The last account signing out keeps its record; with others listed the record goes.
        s = s.signedOutRecord("r1")
        assertEquals(RosterMemory(7, "sealed-7"), s.roster(server, "u1"))
        s = s.signedIn("r1", "u1@example.com", tokens, bundle("u1"), emptySet())
        assertEquals(7L, s.roster(server, "u1").seen)
        s = s.withoutRecord("r1")
        assertEquals(7L, s.roster(server, "u1").seen)
    }

    @Test
    fun anotherAccountOnTheSameRecordDoesntInheritIt() {
        var s = signedInAs("u1").rememberingRoster(server, "u1", 7, "sealed-7").signedOutRecord("r1")
        s = s.signedIn("r1", "u2@example.com", tokens, bundle("u2"), emptySet())
        assertEquals(RosterMemory(), s.roster(server, "u2"))
        // The same user id on another server is another account too.
        assertEquals(RosterMemory(), s.roster("https://other.example", "u1"))
        assertEquals(7L, s.roster(server, "u1").seen)
    }

    @Test
    fun theVersionNeverGoesDown() {
        val s = signedInAs("u1").rememberingRoster(server, "u1", 7, "sealed-7")
        assertEquals(s, s.rememberingRoster(server, "u1", 6, "sealed-6"))
        assertEquals(RosterMemory(8, null), s.rememberingRoster(server, "u1", 8, null).roster(server, "u1"))
        assertEquals(RosterMemory(), s.forgettingRoster(server, "u1").roster(server, "u1"))
    }

    @Test
    fun oldRecordMemoryMovesToTheRecordsAccountOnceOrIsDropped() {
        val old = Stored(
            accounts = mapOf(
                "r1" to AccountData(server = server, email = "a@example.com", bundle = bundle("u1"), rosterSeen = 5, rosterTrusted = "sealed-5"),
                // No bundle: whose memory this was can't be told.
                "r2" to AccountData(server = server, email = "b@example.com", rosterSeen = 3, rosterTrusted = "sealed-3"),
            ),
        )
        val s = old.migrated()
        assertEquals(RosterMemory(5, "sealed-5"), s.roster(server, "u1"))
        assertEquals(1, s.rosters.size)
        s.accounts.values.forEach {
            assertEquals(0L, it.rosterSeen)
            assertNull(it.rosterTrusted)
        }
        assertEquals(s, s.migrated())
        // Written without the old fields; read back the same.
        val json = AppJson.encodeToString(Stored.serializer(), s)
        assertEquals(false, json.contains("rosterSeen"))
        assertEquals(s, AppJson.decodeFromString(Stored.serializer(), json).migrated())
    }
}
