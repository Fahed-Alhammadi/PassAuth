package io.passauth.app

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The app's wrappers over the core's site logic (the semantics themselves are pinned by the
 * golden vectors, GoldenVectorsTest) and the app's own address parsing.
 */
class UrlMatcherTest {
    @Test
    fun parseNormalisesLikeTheBrowser() {
        val p = UrlMatcher.parse("HTTPS://Example.com:443")!!
        assertEquals("https", p.scheme)
        assertEquals("example.com", p.host)
        assertEquals("https://example.com/", p.href)
        assertEquals("example.com:8443", UrlMatcher.parse("example.com:8443/x")!!.host)
        assertEquals("https://example.com/login?a=1#f", UrlMatcher.parse("example.com/login?a=1#f")!!.href)
        assertNull(UrlMatcher.parse("https://exa mple.com"))
        // Internationalised names in ASCII, as the core (and browsers) convert them: UTS #46 keeps ß.
        assertEquals("xn--strae-oqa.de", UrlMatcher.parse("https://straße.de/login")?.hostname)
        assertEquals("xn--bcher-kva.de:8443", UrlMatcher.parse("BÜCHER.de:8443")?.host)
        assertEquals("https://xn--bcher-kva.de", UrlMatcher.parse("https://bücher.de/x")?.origin)
    }

    @Test
    fun theWrappersPassTheItemsMatchTheSettingAndTheVault() {
        fun m(page: String, url: String, match: UrlMatch, fallback: UrlMatch = UrlMatch.Domain, allowRegex: Boolean = true) =
            UrlMatcher.matches(page, LoginUrl(url, match), fallback, allowRegex)
        assertTrue(m("https://login.example.com/a", "https://www.example.com", UrlMatch.Domain))
        assertFalse(m("https://login.example.com/a", "https://www.example.com", UrlMatch.Host))
        // "Default" follows the user's setting.
        assertTrue(m("https://a.example.com", "https://b.example.com", UrlMatch.Default, UrlMatch.Domain))
        assertFalse(m("https://a.example.com", "https://b.example.com", UrlMatch.Default, UrlMatch.Host))
        assertFalse(m("https://example.com", "https://example.com", UrlMatch.Default, UrlMatch.Never))
        // Regular expressions only for the user's own logins, also through "default".
        assertTrue(m("https://accounts.example.com/x", "^https://accounts\\.example\\.com/", UrlMatch.Regex))
        assertFalse(m("https://accounts.example.com/x", "^https://accounts\\.example\\.com/", UrlMatch.Regex, allowRegex = false))
        assertFalse(m("https://accounts.example.com/x", ".*", UrlMatch.Default, UrlMatch.Regex, allowRegex = false))
        assertTrue(m("https://accounts.example.com/x", ".*", UrlMatch.Default, UrlMatch.Regex))
        // The full Public Suffix List: names under a dynamic-DNS suffix are sites of their own.
        assertFalse(m("https://attacker.myfritz.net/", "https://nas.myfritz.net", UrlMatch.Domain))
        assertEquals("nas.myfritz.net", UrlMatcher.baseDomain("x.nas.myfritz.net"))
    }

    @Test
    fun anyWebsiteOfALogin() {
        val login = Login(urls = listOf(LoginUrl("androidapp://com.example.app"), LoginUrl("https://example.org"), LoginUrl("https://example.com", UrlMatch.Host)))
        assertTrue(UrlMatcher.matchesAny("https://example.com/login", login))
        assertFalse(UrlMatcher.matchesAny("https://www.example.com/login", login))
        val byDefault = Login(urls = listOf(LoginUrl("https://example.com")))
        assertTrue(UrlMatcher.matchesAny("https://www.example.com/", byDefault, UrlMatch.Domain))
        assertFalse(UrlMatcher.matchesAny("https://www.example.com/", byDefault, UrlMatch.Host))
        assertFalse(UrlMatcher.matchesAny("https://example.com/", Login()))
        // An app address is never a website, whatever its labels.
        assertFalse(UrlMatcher.matchesAny("https://com.example.app/", Login(urls = listOf(LoginUrl("androidapp://com.example.app", UrlMatch.Host)))))
    }

    @Test
    fun downgradeAndRegexErrors() {
        assertTrue(UrlMatcher.downgrade("http://example.com", LoginUrl("https://example.com", UrlMatch.Domain)))
        assertFalse(UrlMatcher.downgrade("https://example.com", LoginUrl("https://example.com", UrlMatch.Domain)))
        assertFalse(UrlMatcher.downgrade("http://localhost:8080", LoginUrl("https://localhost", UrlMatch.Host)))
        assertTrue(UrlMatcher.downgrade("http://example.com/", LoginUrl("^https://example", UrlMatch.Regex)))
        assertFalse(UrlMatcher.downgrade("http://localhost/x", LoginUrl("^https://localhost", UrlMatch.Regex)))
        // One linear-time engine: nested quantifiers run, unsupported syntax says why.
        assertNull(UrlMatcher.regexError("(a+)+$"))
        assertNull(UrlMatcher.regexError("^https://accounts\\.example\\.com/"))
        assertEquals("Look-around is not supported.", UrlMatcher.regexError("(?<=a)b"))
        assertEquals("The pattern is longer than 300 characters.", UrlMatcher.regexError("a".repeat(301)))
    }

    /** The item editor's note under a website run as a regular expression (the core's resolveMatch, regexError, regexWarning). */
    @Test
    fun patternNotesOnlyForWebsitesRunAsPatterns() {
        // Not tied to one website: the warning.
        assertEquals(UrlMatcher.PATTERN_WARNING, UrlMatcher.patternNote("bank\\.com", UrlMatch.Regex, UrlMatch.Domain))
        assertEquals(UrlMatcher.PATTERN_WARNING, UrlMatcher.patternNote("https://bank\\.com/", UrlMatch.Regex, UrlMatch.Domain))
        // Pinned to its website: nothing to say.
        assertNull(UrlMatcher.patternNote("^https://bank\\.com/", UrlMatch.Regex, UrlMatch.Domain))
        assertNull(UrlMatcher.patternNote("  ^https://bank\\.com/login  ", UrlMatch.Regex, UrlMatch.Domain))
        // Refused by the core: its reason.
        assertEquals("This pattern never matches a page: Look-around is not supported.", UrlMatcher.patternNote("(?<=a)b", UrlMatch.Regex, UrlMatch.Domain))
        // "Default" while the default is "Regular expression": a pattern counts, a plain address is matched by domain.
        assertEquals(UrlMatcher.PATTERN_WARNING, UrlMatcher.patternNote("bank\\.com", UrlMatch.Default, UrlMatch.Regex))
        assertNull(UrlMatcher.patternNote("https://bank.com", UrlMatch.Default, UrlMatch.Regex))
        // Any other match type, and blank entries: never.
        assertNull(UrlMatcher.patternNote("bank\\.com", UrlMatch.Domain, UrlMatch.Regex))
        assertNull(UrlMatcher.patternNote("bank\\.com", UrlMatch.Default, UrlMatch.Domain))
        assertNull(UrlMatcher.patternNote("(?<=a)b", UrlMatch.StartsWith, UrlMatch.Regex))
        assertNull(UrlMatcher.patternNote("   ", UrlMatch.Regex, UrlMatch.Domain))
        assertEquals(
            "This pattern isn't tied to one website, so it could match other sites. Start it with ^https://example\\.com/ (your site's address).",
            UrlMatcher.PATTERN_WARNING,
        )
    }
}
