package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillMatcherTest {
    private val own = "io.passauth.app"
    private fun login(vararg urls: String, user: String = "me", pw: String = "pw", match: UrlMatch = UrlMatch.Default) =
        Login(username = user, password = pw, urls = urls.map { LoginUrl(it, match) })

    private val web = FillTarget.Web("https", "login.example.com")
    private val app = FillTarget.App("com.example.app")

    @Test
    fun resolveTarget() {
        // A browser's web content is matched by website.
        assertEquals(FillTarget.Web("https", "example.com"), FillTarget.resolve("com.android.chrome", "Example.com", "https", true, false, own))
        // Unknown scheme counts as https; other schemes are never filled.
        assertEquals(FillTarget.Web("https", "example.com"), FillTarget.resolve("com.android.chrome", "example.com", null, true, false, own))
        assertNull(FillTarget.resolve("com.android.chrome", "example.com", "ftp", true, false, own))
        // A browser's own UI (address bar): the browser's package name is never used to match.
        assertNull(FillTarget.resolve("com.android.chrome", null, null, true, false, own))
        // An app's WebView: its web domain counts only when its asset links list the app.
        assertEquals(FillTarget.App("com.evil"), FillTarget.resolve("com.evil", "bank.com", "https", false, false, own))
        assertEquals(FillTarget.Web("https", "bank.com"), FillTarget.resolve("com.bank", "bank.com", "https", false, true, own))
        // A native app.
        assertEquals(FillTarget.App("com.example.app"), FillTarget.resolve("com.example.app", null, null, false, false, own))
        // PassAuth itself.
        assertNull(FillTarget.resolve(own, null, null, false, false, own))
    }

    @Test
    fun webMatchingUsesTheDefaultMatchSetting() {
        assertTrue(AutofillMatcher.matches(web, login("https://example.com"), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(web, login("https://example.com"), UrlMatch.Host))
        assertTrue(AutofillMatcher.matches(web, login("https://login.example.com", match = UrlMatch.Host), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(web, login("https://example.org"), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(web, login("https://example.com", match = UrlMatch.Never), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(web, login(), UrlMatch.Domain))
    }

    @Test
    fun androidAppLogins() {
        assertTrue(AutofillMatcher.matches(app, login("androidapp://com.example.app"), UrlMatch.Domain))
        assertTrue(AutofillMatcher.matches(app, login("https://example.com", "androidapp://COM.example.app/"), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(app, login("androidapp://com.example.app.other"), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(app, login("androidapp://com.example.app", match = UrlMatch.Never), UrlMatch.Domain))
        // Web logins never match apps, and app logins never match websites
        // (androidapp://com.example.app must not count as the site example.app).
        assertFalse(AutofillMatcher.matches(app, login("https://example.app"), UrlMatch.Domain))
        assertFalse(AutofillMatcher.matches(FillTarget.Web("https", "example.app"), login("androidapp://com.example.app"), UrlMatch.Domain))
    }

    @Test
    fun refusesHttpsToHttpDowngrade() {
        val http = FillTarget.Web("http", "example.com")
        assertFalse(AutofillMatcher.matches(http, login("https://example.com"), UrlMatch.Domain))
        assertTrue(AutofillMatcher.matches(http, login("http://example.com"), UrlMatch.Domain))
        assertTrue(AutofillMatcher.matches(FillTarget.Web("https", "example.com"), login("http://example.com"), UrlMatch.Domain))
        // Local development hosts are exempt, like in the extension.
        assertTrue(AutofillMatcher.matches(FillTarget.Web("http", "localhost"), login("https://localhost"), UrlMatch.Host))
    }

    @Test
    fun vaultPageAndNeverSaveKeys() {
        assertTrue(AutofillMatcher.isVaultPage(FillTarget.Web("https", "vault.example.com"), "https://vault.example.com/app"))
        assertFalse(AutofillMatcher.isVaultPage(FillTarget.Web("https", "example.com"), "https://vault.example.com"))
        assertFalse(AutofillMatcher.isVaultPage(app, "https://vault.example.com"))
        assertEquals("example.com", AutofillMatcher.neverSaveKey(web))
        assertEquals("androidapp://com.example.app", AutofillMatcher.neverSaveKey(app))
        assertEquals("https://login.example.com", AutofillMatcher.saveUrl(web))
        assertEquals("http://10.0.2.2:8093", AutofillMatcher.saveUrl(FillTarget.Web("http", "10.0.2.2:8093")))
        assertEquals("androidapp://com.example.app", AutofillMatcher.saveUrl(app))
    }

    @Test
    fun planSave() {
        val logins = listOf("a" to login("androidapp://com.example.app", user = "Me", pw = "old"), "b" to login("https://example.com", user = "me", pw = "x"))
        val all = { _: String -> true }
        assertEquals(AutofillMatcher.SavePlan.Update("a"), AutofillMatcher.planSave(app, "me", "new", logins, UrlMatch.Domain, all))
        assertEquals(AutofillMatcher.SavePlan.Nothing, AutofillMatcher.planSave(app, "me", "old", logins, UrlMatch.Domain, all))
        assertEquals(AutofillMatcher.SavePlan.New, AutofillMatcher.planSave(app, "other", "new", logins, UrlMatch.Domain, all))
        assertEquals(AutofillMatcher.SavePlan.Nothing, AutofillMatcher.planSave(app, "me", "new", logins, UrlMatch.Domain) { false })
        assertEquals(AutofillMatcher.SavePlan.Nothing, AutofillMatcher.planSave(app, "me", "", logins, UrlMatch.Domain, all))
        assertEquals(AutofillMatcher.SavePlan.Update("b"), AutofillMatcher.planSave(web, "ME", "y", logins, UrlMatch.Domain, all))
    }
}
