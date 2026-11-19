package io.passauth.app.autofill

import io.passauth.app.credentials.AssetLinks
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.UrlMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLinksTest {
    private val base: (String) -> String = UrlMatcher::baseDomain
    private fun login(vararg urls: String, match: UrlMatch = UrlMatch.Default) = Login(username = "me", password = "pw", urls = urls.map { LoginUrl(it, match) })

    @Test
    fun packageNamesSpellDomainsBackwards() {
        assertEquals(listOf("instagram.com"), AppLinks.packageDomains("com.instagram.android"))
        assertEquals(listOf("google.com", "android.google.com", "gm.android.google.com"), AppLinks.packageDomains("com.google.android.gm"))
        assertEquals(listOf("example.de", "bank.example.de"), AppLinks.packageDomains("de.example.bank.mobile.app"))
        assertEquals(emptyList<String>(), AppLinks.packageDomains("single"))
    }

    @Test
    fun candidatesOnlyForDomainsWithLogins() {
        val bases = AppLinks.loginBases(
            listOf(login("https://www.instagram.com/accounts/login"), login("https://mail.google.com"), login("https://amazon.de")),
            base,
        )
        assertEquals(setOf("instagram.com", "google.com", "amazon.de"), bases)
        assertEquals(listOf("instagram.com"), AppLinks.candidates("com.instagram.android", bases, base))
        assertEquals(listOf("google.com"), AppLinks.candidates("com.google.android.gm", bases, base))
        // A distinctive part of the package names a login's domain under another top-level domain.
        assertEquals(listOf("amazon.de"), AppLinks.candidates("com.amazon.mShop.android.shopping", bases, base))
        // Nothing saved for the app's domain: nothing to check.
        assertEquals(emptyList<String>(), AppLinks.candidates("com.example.notes", bases, base))
        assertEquals(emptyList<String>(), AppLinks.candidates("com.instagram.android", emptySet(), base))
        // Filler parts ("android", "app") never count as a brand.
        assertEquals(emptyList<String>(), AppLinks.candidates("org.app.android", setOf("app.com", "android.com"), base))
    }

    @Test
    fun candidatesAreBounded() {
        val bases = setOf("shop.com", "shop.de", "shop.fr", "shop.it", "shop.es")
        assertEquals(AppLinks.MAX_CANDIDATES, AppLinks.candidates("com.shop.client", bases, base).size)
    }

    @Test
    fun neverAndRegexWebsitesDontLink() {
        assertTrue(AppLinks.isLinkedUrl(LoginUrl("https://login.instagram.com", UrlMatch.Host), setOf("instagram.com"), base))
        assertFalse(AppLinks.isLinkedUrl(LoginUrl("https://instagram.com", UrlMatch.Never), setOf("instagram.com"), base))
        assertFalse(AppLinks.isLinkedUrl(LoginUrl("^https://instagram\\.com", UrlMatch.Regex), setOf("instagram.com"), base))
        assertFalse(AppLinks.isLinkedUrl(LoginUrl("https://instagram.com.evil.net", UrlMatch.Default), setOf("instagram.com"), base))
        assertFalse(AppLinks.isLinkedUrl(LoginUrl("https://instagram.com", UrlMatch.Default), emptySet(), base))
    }

    @Test
    fun verifiedAppGetsTheSitesLogins() {
        val ig = login("https://www.instagram.com")
        val other = login("https://example.com")
        val plain = FillTarget.App("com.instagram.android")
        // A guess alone (no asset links): nothing is suggested.
        assertFalse(AutofillMatcher.matches(plain, ig, UrlMatch.Domain, allowRegex = true))
        // Verified for instagram.com: its logins match, other sites' don't.
        val linked = plain.copy(linkedDomains = setOf("instagram.com"))
        assertTrue(AutofillMatcher.matches(linked, ig, UrlMatch.Domain, allowRegex = true))
        assertFalse(AutofillMatcher.matches(linked, other, UrlMatch.Domain, allowRegex = true))
        // Saving in the app still uses its own address.
        assertEquals("androidapp://com.instagram.android", AutofillMatcher.saveUrl(linked))
        assertEquals("androidapp://com.instagram.android", AutofillMatcher.neverSaveKey(linked))
    }

    @Test
    fun assetLinksVerifyTheAppForAutofill() {
        // A fake asset links file (as the verifier would fetch it): get_login_creds or handle_all_urls.
        val fp = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
        fun file(relation: String, pkg: String = "com.instagram.android") =
            """[{"relation":["$relation"],"target":{"namespace":"android_app","package_name":"$pkg","sha256_cert_fingerprints":["$fp"]}}]"""
        val rel = AssetLinks.APP_LOGIN_RELATIONS
        assertTrue(AssetLinks.allows(file(AssetLinks.GET_LOGIN_CREDS), "com.instagram.android", listOf(fp), rel))
        assertTrue(AssetLinks.allows(file(AssetLinks.HANDLE_ALL_URLS), "com.instagram.android", listOf(fp), rel))
        // Passkeys keep requiring get_login_creds.
        assertFalse(AssetLinks.allows(file(AssetLinks.HANDLE_ALL_URLS), "com.instagram.android", listOf(fp)))
        // Another package, or the right package signed with another certificate (a look-alike app): no.
        assertFalse(AssetLinks.allows(file(AssetLinks.GET_LOGIN_CREDS, "com.instagram.android.fake"), "com.instagram.android", listOf(fp), rel))
        assertFalse(AssetLinks.allows(file(AssetLinks.GET_LOGIN_CREDS), "com.instagram.android", listOf(fp.replace("14:6D", "00:00")), rel))
        assertFalse(AssetLinks.allows(file("delegate_permission/common.something_else"), "com.instagram.android", listOf(fp), rel))
        assertEquals(listOf("instagram.com", "www.instagram.com"), AppLinks.assetLinkHosts("instagram.com"))
    }
}
