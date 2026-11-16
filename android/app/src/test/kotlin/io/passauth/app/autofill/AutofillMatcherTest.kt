package io.passauth.app.autofill

import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Role
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.VaultData
import io.passauth.app.data.VaultInfo
import io.passauth.core.EncryptedItem
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
        assertTrue(AutofillMatcher.matches(web, login("https://example.com"), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(web, login("https://example.com"), UrlMatch.Host, allowRegex = true))
        assertTrue(AutofillMatcher.matches(web, login("https://login.example.com", match = UrlMatch.Host), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(web, login("https://example.org"), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(web, login("https://example.com", match = UrlMatch.Never), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(web, login(), UrlMatch.Domain, allowRegex = true))
    }

    @Test
    fun androidAppLogins() {
        assertTrue(AutofillMatcher.matches(app, login("androidapp://com.example.app"), UrlMatch.Domain, allowRegex = true))
        assertTrue(AutofillMatcher.matches(app, login("https://example.com", "androidapp://COM.example.app/"), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(app, login("androidapp://com.example.app.other"), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(app, login("androidapp://com.example.app", match = UrlMatch.Never), UrlMatch.Domain, allowRegex = true))
        // Web logins never match apps, and app logins never match websites
        // (androidapp://com.example.app must not count as the site example.app).
        assertFalse(AutofillMatcher.matches(app, login("https://example.app"), UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(FillTarget.Web("https", "example.app"), login("androidapp://com.example.app"), UrlMatch.Domain, allowRegex = true))
    }

    @Test
    fun refusesHttpsToHttpDowngrade() {
        val http = FillTarget.Web("http", "example.com")
        assertFalse(AutofillMatcher.matches(http, login("https://example.com"), UrlMatch.Domain, allowRegex = true))
        assertTrue(AutofillMatcher.matches(http, login("http://example.com"), UrlMatch.Domain, allowRegex = true))
        assertTrue(AutofillMatcher.matches(FillTarget.Web("https", "example.com"), login("http://example.com"), UrlMatch.Domain, allowRegex = true))
        // Local development hosts are exempt, like in the extension.
        assertTrue(AutofillMatcher.matches(FillTarget.Web("http", "localhost"), login("https://localhost"), UrlMatch.Host, allowRegex = true))
    }

    @Test
    fun vaultPageIsAnOrdinarySiteAndNeverSaveKeys() {
        // The PassAuth server's own web vault is filled like any website.
        assertTrue(AutofillMatcher.matches(FillTarget.Web("https", "vault.example.com"), login("https://vault.example.com"), UrlMatch.Domain, allowRegex = true))
        assertEquals("example.com", AutofillMatcher.neverSaveKey(web))
        assertEquals("androidapp://com.example.app", AutofillMatcher.neverSaveKey(app))
        assertEquals("https://login.example.com", AutofillMatcher.saveUrl(web))
        assertEquals("http://10.0.2.2:8093", AutofillMatcher.saveUrl(FillTarget.Web("http", "10.0.2.2:8093")))
        assertEquals("androidapp://com.example.app", AutofillMatcher.saveUrl(app))
    }

    @Test
    fun saveCandidatesAreTheMatchingLoginsWithTheirVault() {
        val logins = listOf(
            Triple("a", "App", login("androidapp://com.example.app", user = "Me", pw = "old")),
            Triple("b", "Site", login("https://example.com", user = "me", pw = "x")),
            Triple("s", "Planted", login("androidapp://com.example.app", user = "", pw = "y")),
        )
        val place = { id: String -> if (id == "s") AutofillMatcher.Place(writable = true, personal = false, vault = "Team") else AutofillMatcher.Place(true, true, "Personal") }
        val forApp = AutofillMatcher.saveCandidates(app, logins, UrlMatch.Domain, place)
        assertEquals(listOf("a", "s"), forApp.map { it.id })
        assertEquals(listOf(true, false), forApp.map { it.own })
        assertEquals("Team", forApp[1].vault)
        // The rule over them: the same user name is updated, a new one is a new login (never the planted blank one).
        assertEquals(SaveRule.Plan.Update("a", SaveRule.Reason.Same), SaveRule.plan(forApp, "me", "new"))
        assertEquals(SaveRule.Plan.Nothing, SaveRule.plan(forApp, "me", "old"))
        assertEquals(SaveRule.Plan.New, SaveRule.plan(forApp, "other", "new"))
        assertEquals(SaveRule.Plan.Nothing, SaveRule.plan(forApp, "me", ""))
        val forWeb = AutofillMatcher.saveCandidates(web, logins, UrlMatch.Domain, place)
        assertEquals(listOf("b"), forWeb.map { it.id })
        assertEquals(SaveRule.Plan.Update("b", SaveRule.Reason.Same), SaveRule.plan(forWeb, "ME", "y"))
    }

    /**
     * A website that is a regular expression counts only in the user's own vaults: anyone can
     * share a vault with the user and plant a slow or catch-all pattern there (the extension's
     * `allowRegex`). Fill lists, the password provider and the save rule all use this.
     */
    @Test
    fun regexWebsitesOnlyFromOwnVaults() {
        fun entry(id: String, url: String, match: UrlMatch, vault: String = "v1", user: String = "me") = Entry(
            id = id,
            item = Item(name = id, login = Login(username = user, password = "pw", urls = listOf(LoginUrl(url, match)))),
            vaultId = vault,
            revision = 1,
            enc = EncryptedItem(id = id, vaultId = vault, key = "", data = ""),
        )
        val mine = entry("mine", "^https://login\\.example\\.com/", UrlMatch.Regex)
        val ownDefault = entry("ownDefault", "^https://login\\.example\\.com", UrlMatch.Default)
        val planted = entry("planted", ".*", UrlMatch.Regex, vault = "team", user = "victim")
        val viaDefault = entry("viaDefault", "example\\.com", UrlMatch.Default, vault = "team")
        val sharedSite = entry("site", "https://example.com", UrlMatch.Default, vault = "team")
        val vault = VaultData(
            entries = listOf(mine, ownDefault, planted, viaDefault, sharedSite),
            vaults = listOf(VaultInfo("v1", "Personal", Role.Owner), VaultInfo("team", "Team", Role.Write, keyKind = "sealed")),
        )
        assertTrue(vault.isPersonal(mine))
        assertFalse(vault.isPersonal(planted))
        // The own pattern matches, the shared catch-all doesn't; a shared login's other websites still do.
        assertEquals(listOf("mine", "site"), AutofillMatcher.candidates(web, vault, UrlMatch.Domain).map { it.id })
        // "Default" resolved to a regular expression by the user's setting: patterns only for the own logins; a plain
        // address is never run as a pattern (the core matches it by its domain), so the shared login's own site matches.
        assertEquals(listOf("mine", "ownDefault", "site"), AutofillMatcher.candidates(web, vault, UrlMatch.Regex).map { it.id })
        val plantedLogin = requireNotNull(planted.item.login)
        assertTrue("the pattern itself would match", AutofillMatcher.matches(web, plantedLogin, UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(web, plantedLogin, UrlMatch.Domain, allowRegex = false))
        // A login whose vault is unknown counts as somebody else's.
        assertEquals(listOf("site"), AutofillMatcher.candidates(web, vault.copy(vaults = emptyList()), UrlMatch.Domain).map { it.id })
        // The save rule never sees the planted login: typing its user name saves a new login.
        val place = { id: String ->
            val info = vault.vaults.firstOrNull { v -> v.id == vault.get(id)?.vaultId }
            AutofillMatcher.Place(writable = info != null && info.role != Role.Read, personal = info?.personal == true, vault = info?.name.orEmpty())
        }
        val candidates = AutofillMatcher.saveCandidates(web, vault.entries.map { Triple(it.id, it.item.name, it.item.login!!) }, UrlMatch.Domain, place)
        assertEquals(listOf("mine", "site"), candidates.map { it.id })
        assertEquals(SaveRule.Plan.New, SaveRule.plan(candidates, "victim", "new"))
    }
}
