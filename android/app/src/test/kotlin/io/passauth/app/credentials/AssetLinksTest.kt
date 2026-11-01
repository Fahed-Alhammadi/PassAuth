package io.passauth.app.credentials

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AssetLinksTest {
    private val fp = "14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"
    private val json = """
        [{
          "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
          "target": {"namespace": "android_app", "package_name": "com.example.app", "sha256_cert_fingerprints": ["$fp"]}
        },
        {
          "relation": ["delegate_permission/common.get_login_creds"],
          "target": {"namespace": "web", "site": "https://example.com"}
        },
        {
          "relation": ["delegate_permission/common.handle_all_urls"],
          "target": {"namespace": "android_app", "package_name": "com.example.links", "sha256_cert_fingerprints": ["$fp"]}
        }]
    """.trimIndent()

    @Test
    fun grantsOnlyListedAppsWithTheRelation() {
        assertTrue(AssetLinks.allows(json, "com.example.app", listOf(fp)))
        // Fingerprints compare case-insensitively.
        assertTrue(AssetLinks.allows(json, "com.example.app", listOf("AA:BB", fp.lowercase())))
        assertFalse(AssetLinks.allows(json, "com.example.app", listOf(fp.replace("14:6D", "14:6E"))))
        assertFalse(AssetLinks.allows(json, "com.example.evil", listOf(fp)))
        // handle_all_urls (app links) alone doesn't grant sign-in credentials.
        assertFalse(AssetLinks.allows(json, "com.example.links", listOf(fp)))
        assertFalse(AssetLinks.allows(json, "com.example.app", emptyList()))
    }

    @Test
    fun malformedFilesGrantNothing() {
        assertFalse(AssetLinks.allows("", "com.example.app", listOf(fp)))
        assertFalse(AssetLinks.allows("{}", "com.example.app", listOf(fp)))
        assertFalse(AssetLinks.allows("[1, \"x\", {\"relation\": \"x\"}]", "com.example.app", listOf(fp)))
        assertFalse(AssetLinks.allows("""[{"relation":["delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"com.example.app"}}]""", "com.example.app", listOf(fp)))
    }

    @Test
    fun fingerprintFormat() {
        assertEquals("00:0A:FF", AssetLinks.fingerprint(byteArrayOf(0, 10, -1)))
    }

    @Test
    fun bundledBrowserAllowlist() {
        val apps = PrivilegedApps.parse(File("src/main/res/raw/privileged_allowlist.json").readText())
        assertTrue(apps.keys.containsAll(listOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "org.mozilla.firefox", "com.microsoft.emmx", "com.brave.browser", "com.sec.android.app.sbrowser")))
        assertTrue("F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83" in apps.getValue("com.android.chrome"))
        assertTrue(PrivilegedApps.parse("{}").isEmpty())
    }

    @Test
    fun debugTestBrowserMergesIntoItsPackageEntry() {
        val base = """{"apps":[{"type":"android","info":{"package_name":"org.chromium.chrome","signatures":[{"build":"release","cert_fingerprint_sha256":"AA:BB"}]}}]}"""
        val merged = PrivilegedApps.parse(PrivilegedApps.withTestApp(base, "org.chromium.chrome|CC:DD"))
        assertEquals(setOf("AA:BB", "CC:DD"), merged["org.chromium.chrome"])
        assertEquals(1, Regex("org.chromium.chrome").findAll(PrivilegedApps.withTestApp(base, "org.chromium.chrome|CC:DD")).count())
        val added = PrivilegedApps.parse(PrivilegedApps.withTestApp(base, "com.example.browser|EE:FF"))
        assertEquals(setOf("EE:FF"), added["com.example.browser"])
        // Release builds pass an empty value: the list is unchanged.
        assertEquals(base, PrivilegedApps.withTestApp(base, ""))
    }
}
