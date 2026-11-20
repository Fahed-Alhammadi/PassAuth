package io.passauth.app.autofill

import io.passauth.app.autofill.IdentifierFirst.Step
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentifierFirstTest {
    private fun field(id: String, value: String? = null) = FieldInfo(id = id, value = value)

    @Test
    fun aUserNameStepHasOnlyAUserName() {
        assertTrue(IdentifierFirst.isUsernameStep(LoginForm(field("u"), emptyList(), null)))
        assertFalse(IdentifierFirst.isUsernameStep(LoginForm(field("u"), listOf(field("p")), null)))
        assertFalse(IdentifierFirst.isUsernameStep(LoginForm(null, listOf(field("p")), null)))
        assertFalse(IdentifierFirst.isUsernameStep(LoginForm(field("u"), emptyList(), field("otp"))))
        assertFalse(IdentifierFirst.isUsernameStep(LoginForm<String>(null, emptyList(), null)))
    }

    @Test
    fun theUserNameComesFromTheEarlierScreenOfTheSamePlace() {
        val earlier = listOf(Step("example.com", " alice@example.com ", hasPassword = false))
        assertEquals("alice@example.com", IdentifierFirst.username("", earlier, "example.com", "example.com"))
        // The newest user-name screen wins.
        val two = listOf(Step("example.com", "old", false), Step("example.com", "new", false))
        assertEquals("new", IdentifierFirst.username("", two, "example.com", "example.com"))
    }

    @Test
    fun neverFromAnotherPlaceOrWithoutTheState() {
        val earlier = listOf(Step("evil.example", "alice", false))
        assertEquals("", IdentifierFirst.username("", earlier, "example.com", "example.com"))
        // The state names another place, or none: nothing carried over.
        val same = listOf(Step("example.com", "alice", false))
        assertEquals("", IdentifierFirst.username("", same, "example.com", "other.com"))
        assertEquals("", IdentifierFirst.username("", same, "example.com", null))
        // A screen with a password field isn't a user-name screen; empty user names don't count.
        assertEquals("", IdentifierFirst.username("", listOf(Step("example.com", "alice", true)), "example.com", "example.com"))
        assertEquals("", IdentifierFirst.username("", listOf(Step("example.com", "  ", false)), "example.com", "example.com"))
    }

    @Test
    fun theUserNameOnThePasswordScreenWins() {
        val earlier = listOf(Step("example.com", "alice", false))
        assertEquals("bob", IdentifierFirst.username("bob", earlier, "example.com", "example.com"))
    }

    @Test
    fun continuesOnlyTheSamePlace() {
        assertTrue(IdentifierFirst.continues("androidapp://com.example", "androidapp://com.example"))
        assertFalse(IdentifierFirst.continues("androidapp://com.other", "androidapp://com.example"))
        assertFalse(IdentifierFirst.continues(null, "example.com"))
    }
}
