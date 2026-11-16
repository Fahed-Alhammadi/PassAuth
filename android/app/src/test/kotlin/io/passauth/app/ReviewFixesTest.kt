package io.passauth.app

import io.passauth.app.data.LoginUrl
import io.passauth.app.data.RefreshResult
import io.passauth.app.data.Role
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import io.passauth.app.data.VaultInfo
import io.passauth.app.data.refreshOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ReviewFixesTest {
    private fun m(page: String, url: String, match: UrlMatch) = UrlMatcher.matches(page, LoginUrl(url, match), UrlMatch.Domain)

    @Test
    fun dynamicDnsNamesAreSeparateSites() {
        assertEquals("home.duckdns.org", UrlMatcher.baseDomain("nas.home.duckdns.org"))
        assertEquals("evil.duckdns.org", UrlMatcher.baseDomain("evil.duckdns.org"))
        assertFalse(m("https://evil.duckdns.org/login", "https://home.duckdns.org", UrlMatch.Domain))
        assertTrue(m("https://nas.home.duckdns.org/login", "https://home.duckdns.org", UrlMatch.Domain))
        assertFalse(m("https://x.ddns.net", "https://y.ddns.net", UrlMatch.Domain))
        assertEquals("app.up.railway.app", UrlMatcher.baseDomain("api.app.up.railway.app"))
        assertEquals("duckdns.org", UrlMatcher.baseDomain("duckdns.org"))
    }

    @Test
    fun regexIsBoundedAndIgnoresTheQuery() {
        assertFalse(m("https://evil.com/?bank.com", "bank\\.com", UrlMatch.Regex))
        assertTrue(m("https://bank.com/login?x=1", "^https://bank\\.com/", UrlMatch.Regex))
        // The core's engine runs in linear time: a nested quantifier on a long address returns at once.
        val start = System.nanoTime()
        assertFalse(m("https://${"a".repeat(1900)}.com/", "(a+)+$", UrlMatch.Regex))
        assertTrue("took ${(System.nanoTime() - start) / 1_000_000} ms", System.nanoTime() - start < 2_000_000_000L)
        assertFalse(m("https://example.com/", "x".repeat(301), UrlMatch.Regex))
    }

    @Test
    fun newItemsGoToTheOwnVaultNeverASharedOne() {
        val planted = VaultInfo("a", "Personal", Role.Owner, "sealed")
        val own = VaultInfo("b", "My vault", Role.Owner, "account")
        assertEquals(own, VaultInfo.defaultSaveVault(listOf(planted, own)))
        assertNull(VaultInfo.defaultSaveVault(listOf(planted, VaultInfo("c", "Team", Role.Write, "sealed"))))
        val ownWrite = VaultInfo("d", "Mine", Role.Write, "account")
        assertEquals(ownWrite, VaultInfo.defaultSaveVault(listOf(planted, ownWrite)))
        assertNull(VaultInfo.defaultSaveVault(listOf(VaultInfo("e", "Mine", Role.Read, "account"))))
    }

    @Test
    fun onlyARejectedRefreshEndsTheSession() {
        assertEquals(RefreshResult.Refreshed, refreshOutcome(200))
        for (code in listOf(400, 401, 403)) assertEquals(RefreshResult.Rejected, refreshOutcome(code))
        for (code in listOf(429, 500, 502, 503, 504)) assertEquals(RefreshResult.Unavailable, refreshOutcome(code))
    }
}
