package io.passauth.app.credentials

import io.passauth.app.data.Entry
import io.passauth.app.data.Item
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.Passkey
import io.passauth.app.data.Role
import io.passauth.app.data.UrlMatch
import io.passauth.app.data.VaultData
import io.passauth.app.data.VaultInfo
import io.passauth.core.EncryptedItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyTargetsTest {
    private fun entry(id: String, name: String, user: String, url: String, vault: String = "v1") = Entry(
        id = id,
        item = Item(name = name, login = Login(username = user, password = "pw", urls = listOf(LoginUrl(url, UrlMatch.Default)))),
        vaultId = vault,
        revision = 1,
        enc = EncryptedItem(id = id, vaultId = vault, key = "", data = ""),
    )

    private val cloudy = entry("c", "Cloudy", "fahed", "https://cloudy.example.com")
    private val bazarr = entry("b", "Bazarr", "fahed", "https://bazarr.example.com")
    private val gh = entry("g", "GitHub", "fahed@example.com", "github.com")
    private val ghOther = entry("g2", "GitHub work", "other", "https://github.com/login")
    private val apex = entry("a", "Apex", "x", "https://example.com")
    private val readOnly = entry("r", "Cloudy shared", "fahed", "https://cloudy.example.com", vault = "ro")
    private val vault = VaultData(
        entries = listOf(bazarr, cloudy, gh, ghOther, apex, readOnly),
        vaults = listOf(VaultInfo("v1", "Personal", Role.Owner), VaultInfo("ro", "Shared", Role.Read)),
    )

    @Test
    fun anotherSubdomainOfTheSameBaseDomainIsNeverOffered() {
        val t = PasskeyTargets.saveTargets(vault, "cloudy.example.com", "cloudy.example.com", "fahed")
        assertEquals(listOf("c"), t.map { it.id })
        assertEquals("c", PasskeyTargets.defaultTarget(vault, t, "cloudy.example.com"))
        val n = PasskeyTargets.saveTargets(vault, "new.example.com", "new.example.com", "fahed")
        assertTrue(n.isEmpty())
        assertEquals(PasskeyTargets.NEW_LOGIN, PasskeyTargets.defaultTarget(vault, n, "new.example.com"))
    }

    @Test
    fun rpIdOfTheBaseDomainOffersItsSubdomainsExactHostFirst() {
        val t = PasskeyTargets.saveTargets(vault, "cloudy.example.com", "example.com", "fahed")
        assertEquals("c", t.first().id)
        assertEquals(setOf("a", "b", "c"), t.map { it.id }.toSet())
    }

    @Test
    fun githubUserNameMatchesTheEmailsUserPart() {
        val t = PasskeyTargets.saveTargets(vault, "github.com", "github.com", "fahed", "Fahed")
        assertEquals(listOf("g", "g2"), t.map { it.id })
        assertEquals("g", PasskeyTargets.defaultTarget(vault, t, "github.com"))
    }

    @Test
    fun planUsesOnlyAValidChoice() {
        val p = Passkey(rpId = "cloudy.example.com", userName = "fahed")
        val attach = PasskeyTargets.plan(vault, p, "cloudy.example.com", "c") as PasskeyTargets.Plan.Attach
        assertEquals("c", attach.entry.id)
        assertEquals(listOf(p), attach.item.login?.passkeys)
        // bazarr is another site, r is read-only: both give a new login for the page's host.
        for (target in listOf("b", "r", PasskeyTargets.NEW_LOGIN)) {
            val create = PasskeyTargets.plan(vault, p, "cloudy.example.com", target) as PasskeyTargets.Plan.Create
            assertEquals(listOf(LoginUrl("https://cloudy.example.com", UrlMatch.Default)), create.item.login?.urls)
            assertEquals(listOf(p), create.item.login?.passkeys)
        }
    }

    // ---- shared vaults: anyone on the server can share one and plant a login for the site in it

    private val planted = entry("p", "Cloudy", "fahed", "https://cloudy.example.com", vault = "team")
    private val withPlanted = VaultData(
        entries = listOf(planted, cloudy, apex),
        vaults = listOf(VaultInfo("v1", "Personal", Role.Owner), VaultInfo("team", "Team", Role.Write, keyKind = "vault")),
    )

    @Test
    fun aSharedVaultLoginIsNeverThePreselectedPlaceForAPasskey() {
        // Only a planted login for the exact host: listed (it can be chosen), but the default is a new login.
        val onlyPlanted = withPlanted.copy(entries = listOf(planted))
        val t = PasskeyTargets.saveTargets(onlyPlanted, "cloudy.example.com", "cloudy.example.com", "fahed")
        assertEquals(listOf("p"), t.map { it.id })
        assertEquals(PasskeyTargets.NEW_LOGIN, PasskeyTargets.defaultTarget(onlyPlanted, t, "cloudy.example.com"))
        assertEquals("fahed · Team", PasskeyTargets.detail(onlyPlanted, planted))
    }

    @Test
    fun yourOwnLoginComesFirstAndIsPreselected() {
        // Same host and user name in both vaults: the user's own login wins, the shared one follows.
        val t = PasskeyTargets.saveTargets(withPlanted, "cloudy.example.com", "cloudy.example.com", "fahed")
        assertEquals(listOf("c", "p"), t.map { it.id })
        assertEquals("c", PasskeyTargets.defaultTarget(withPlanted, t, "cloudy.example.com"))
        assertEquals("fahed", PasskeyTargets.detail(withPlanted, cloudy))
        // Your own login for another host of the RP still isn't preselected over "New login"...
        val sub = PasskeyTargets.saveTargets(withPlanted.copy(entries = listOf(planted, apex)), "cloudy.example.com", "example.com", "fahed")
        assertEquals(listOf("a", "p"), sub.map { it.id })
        // ...and neither is the planted exact-host one.
        assertEquals(PasskeyTargets.NEW_LOGIN, PasskeyTargets.defaultTarget(withPlanted, sub, "cloudy.example.com"))
    }

    @Test
    fun aSharedVaultLoginCanStillBeChosen() {
        val p = Passkey(rpId = "cloudy.example.com", userName = "fahed")
        val attach = PasskeyTargets.plan(withPlanted, p, "cloudy.example.com", "p") as PasskeyTargets.Plan.Attach
        assertEquals("p", attach.entry.id)
    }

    @Test
    fun hostComesFromTheBrowserOriginElseTheRpId() {
        assertEquals("cloudy.example.com", PasskeyTargets.hostOf("https://Cloudy.Example.com:8443", "example.com"))
        assertEquals("example.com", PasskeyTargets.hostOf("android:apk-key-hash:abc", "Example.com"))
    }
}
