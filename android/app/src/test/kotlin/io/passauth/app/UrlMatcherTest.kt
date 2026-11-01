package io.passauth.app

import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Same cases as the extension's urls.ts semantics. */
class UrlMatcherTest {
    private fun m(page: String, url: String, match: UrlMatch, fallback: UrlMatch = UrlMatch.Domain) =
        UrlMatcher.matches(page, LoginUrl(url, match), fallback)

    @Test
    fun baseDomain() {
        assertEquals("example.com", UrlMatcher.baseDomain("login.example.com"))
        assertEquals("example.com", UrlMatcher.baseDomain("Example.COM."))
        assertEquals("example.co.uk", UrlMatcher.baseDomain("www.example.co.uk"))
        assertEquals("co.uk", UrlMatcher.baseDomain("co.uk"))
        assertEquals("me.github.io", UrlMatcher.baseDomain("a.me.github.io"))
        assertEquals("192.168.1.10", UrlMatcher.baseDomain("192.168.1.10"))
        assertEquals("localhost", UrlMatcher.baseDomain("localhost"))
        assertEquals("[::1]", UrlMatcher.baseDomain("[::1]"))
    }

    @Test
    fun parseNormalisesLikeTheBrowser() {
        val p = UrlMatcher.parse("HTTPS://Example.com:443")!!
        assertEquals("https", p.scheme)
        assertEquals("example.com", p.host)
        assertEquals("https://example.com/", p.href)
        assertEquals("example.com:8443", UrlMatcher.parse("example.com:8443/x")!!.host)
        assertEquals("https://example.com/login?a=1#f", UrlMatcher.parse("example.com/login?a=1#f")!!.href)
        assertNull(UrlMatcher.parse("https://exa mple.com"))
    }

    @Test
    fun domainMatch() {
        assertTrue(m("https://login.example.com/a", "https://www.example.com", UrlMatch.Domain))
        assertTrue(m("https://example.com", "example.com", UrlMatch.Domain))
        assertFalse(m("https://example.org", "https://example.com", UrlMatch.Domain))
        assertFalse(m("https://a.co.uk", "https://b.co.uk", UrlMatch.Domain))
        assertFalse(m("https://evil-example.com", "https://example.com", UrlMatch.Domain))
    }

    @Test
    fun hostMatchIncludesPort() {
        assertTrue(m("https://login.example.com/x", "https://login.example.com", UrlMatch.Host))
        assertFalse(m("https://www.example.com", "https://login.example.com", UrlMatch.Host))
        assertFalse(m("https://example.com:8443", "https://example.com", UrlMatch.Host))
        assertTrue(m("https://example.com:443/", "https://example.com", UrlMatch.Host))
    }

    @Test
    fun startsWithAndExact() {
        assertTrue(m("https://example.com/app/login", "https://example.com/app", UrlMatch.StartsWith))
        assertFalse(m("https://example.com/other", "https://example.com/app", UrlMatch.StartsWith))
        assertTrue(m("https://example.com", "https://example.com/", UrlMatch.Exact))
        assertFalse(m("https://example.com/login", "https://example.com/", UrlMatch.Exact))
    }

    @Test
    fun regexAndNever() {
        assertTrue(m("https://Accounts.Example.com/signin", "^https://accounts\\.example\\.com/", UrlMatch.Regex))
        assertFalse(m("https://example.com", "(", UrlMatch.Regex))
        assertFalse(m("https://example.com", "https://example.com", UrlMatch.Never))
    }

    @Test
    fun defaultFollowsTheSetting() {
        assertTrue(m("https://a.example.com", "https://b.example.com", UrlMatch.Default, UrlMatch.Domain))
        assertFalse(m("https://a.example.com", "https://b.example.com", UrlMatch.Default, UrlMatch.Host))
        assertFalse(m("https://example.com", "https://example.com", UrlMatch.Default, UrlMatch.Never))
    }

    @Test
    fun onlyWebPagesMatch() {
        assertFalse(m("ftp://example.com", "https://example.com", UrlMatch.Domain))
        assertFalse(m("not a url", "https://example.com", UrlMatch.Domain))
    }

    @Test
    fun downgrade() {
        assertTrue(UrlMatcher.downgrade("http://example.com", LoginUrl("https://example.com", UrlMatch.Domain)))
        assertFalse(UrlMatcher.downgrade("https://example.com", LoginUrl("https://example.com", UrlMatch.Domain)))
        assertFalse(UrlMatcher.downgrade("http://localhost:8080", LoginUrl("https://localhost", UrlMatch.Host)))
        assertTrue(UrlMatcher.downgrade("http://example.com/", LoginUrl("^https://example", UrlMatch.Regex)))
        assertFalse(UrlMatcher.downgrade("http://localhost/x", LoginUrl("^https://localhost", UrlMatch.Regex)))
    }
}
