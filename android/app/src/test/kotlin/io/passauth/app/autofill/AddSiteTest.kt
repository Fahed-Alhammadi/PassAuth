package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AddSiteTest {
    private val web = FillTarget.Web("https", "play.google.com")
    private val app = FillTarget.App("com.example.mail")

    private fun login(vararg urls: String, user: String = "me@example.com", pw: String = "pw") =
        Login(username = user, password = pw, urls = urls.map { LoginUrl(it, UrlMatch.Default) })

    private val own = AutofillMatcher.Place(writable = true, personal = true, vault = "Personal")
    private val readOnly = AutofillMatcher.Place(writable = false, personal = false, vault = "Family")
    private val shared = AutofillMatcher.Place(writable = true, personal = false, vault = "Team")

    @Test
    fun addressIsTheOriginForWebAndThePackageForApps() {
        assertEquals("https://play.google.com", AddSite.address(web))
        assertEquals("http://intranet.example", AddSite.address(FillTarget.Web("http", "intranet.example")))
        assertEquals("androidapp://com.example.mail", AddSite.address(app))
    }

    @Test
    fun neverForAnUnverifiedWebView() {
        assertTrue(AddSite.allowed(web, "play.google.com"))
        assertTrue(AddSite.allowed(app, null))
        // An app's WebView whose domain doesn't list the app resolves to the app: nothing is offered.
        assertFalse(AddSite.allowed(FillTarget.App("com.evil"), "accounts.google.com"))
    }

    @Test
    fun targetsExcludeMatchingAndReadOnlyLogins() {
        val logins = listOf(
            Triple("gmail", "Gmail", login("https://mail.google.com")),
            Triple("play", "Play", login("https://play.google.com")),
            Triple("ro", "Read only", login("https://example.org")),
            Triple("team", "Team", login("https://team.example")),
            Triple("mailapp", "Mail app", login("androidapp://com.example.mail")),
        )
        val places = mapOf("ro" to readOnly, "team" to shared)
        val forWeb = AddSite.targets(web, logins, UrlMatch.Host, { places[it] ?: own }).map { it.id }
        // play matches the page; ro can't be edited; own vault first, then shared.
        assertEquals(listOf("gmail", "mailapp", "team"), forWeb)
        // With the domain default, mail.google.com already matches play.google.com.
        assertEquals(listOf("mailapp", "team"), AddSite.targets(web, logins, UrlMatch.Domain, { places[it] ?: own }).map { it.id })
        // The app: its own login matches already.
        assertEquals(listOf("gmail", "play", "team"), AddSite.targets(app, logins, UrlMatch.Domain, { places[it] ?: own }).map { it.id })
        val g = AddSite.targets(web, logins, UrlMatch.Host, { places[it] ?: own }).first()
        assertEquals("mail.google.com", g.site)
        assertEquals("com.example.mail", AddSite.siteOf(login("androidapp://com.example.mail/")))
    }

    @Test
    fun addAppendsWithDefaultMatchAndIsANoOpWhenAlreadyMatching() {
        val l = login("https://mail.google.com")
        val added = AddSite.withSite(l, web)
        assertEquals(listOf(LoginUrl("https://mail.google.com", UrlMatch.Default), LoginUrl("https://play.google.com", UrlMatch.Default)), added.urls)
        assertEquals(l.username, added.username)
        assertEquals(l.password, added.password)
        assertTrue(AddSite.alreadyMatches(web, added, UrlMatch.Host, personal = true))
        assertFalse(AddSite.alreadyMatches(web, l, UrlMatch.Host, personal = true))
        val appAdded = AddSite.withSite(l, app)
        assertEquals(LoginUrl("androidapp://com.example.mail", UrlMatch.Default), appAdded.urls.last())
        assertTrue(AddSite.alreadyMatches(app, appAdded, UrlMatch.Domain, personal = true))
    }

    @Test
    fun sameAccountElsewhereNeedsUserAndPasswordOwnVaultNoSiteTargetsMaxThree() {
        val logins = listOf(
            Triple("a", "A", login("https://a.example", user = "Me@Example.com ")),
            Triple("b", "B", login("https://b.example", pw = "other")),
            Triple("c", "C", login("https://c.example", user = "someone")),
            Triple("shared", "Shared", login("https://s.example")),
            Triple("ro", "RO", login("https://r.example")),
            Triple("d", "D", login("https://d.example")),
            Triple("e", "E", login("https://e.example")),
            Triple("f", "F", login("https://f.example")),
        )
        val places = mapOf("shared" to shared, "ro" to AutofillMatcher.Place(writable = false, personal = true))
        fun run(user: String, pw: String, siteTargets: List<*> = emptyList<Any>()) =
            AddSite.sameAccountElsewhere(web, logins, UrlMatch.Domain, { places[it] ?: own }, user, pw, siteTargets).map { it.id }
        // Case-insensitive, trimmed user name; exact password; own editable vault only; at most 3.
        assertEquals(listOf("a", "d", "e"), run(" me@EXAMPLE.com", "pw"))
        // Password must be exactly the same.
        assertEquals(emptyList<String>(), run("me@example.com", "PW"))
        // Both must be typed.
        assertEquals(emptyList<String>(), run("", "pw"))
        assertEquals(emptyList<String>(), run("me@example.com", ""))
        // Only when the save has nothing for this site.
        assertEquals(emptyList<String>(), run("me@example.com", "pw", listOf("x")))
        // A login already matching the place is never a row.
        val matching = listOf(Triple("p", "P", login("https://play.google.com")))
        assertEquals(emptyList<String>(), AddSite.sameAccountElsewhere(web, matching, UrlMatch.Domain, { own }, "me@example.com", "pw", emptyList<Any>()))
    }

    @Test
    fun texts() {
        val t = AddSite.Target("a", "Gmail", "me", "mail.google.com", personal = true)
        assertEquals("Adds play.google.com to Gmail. Its user name and password stay the same, and it is suggested here from now on.", AddSite.describe(t, "play.google.com"))
        assertEquals("Only add it if play.google.com uses the same account as mail.google.com.", AddSite.warning(t, "play.google.com"))
        assertEquals(null, AddSite.sharedWarning(t))
        assertTrue(AddSite.sharedWarning(t.copy(personal = false, vault = "Team"))!!.contains("Team"))
    }
}
