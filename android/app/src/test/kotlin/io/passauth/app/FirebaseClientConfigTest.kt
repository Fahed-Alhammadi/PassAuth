package io.passauth.app

import FirebaseClientConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** buildSrc's reading of `google-services.json` (BuildConfig fields of each variant). Fictional values. */
class FirebaseClientConfigTest {
    private val json = """
        {
          "project_info": {"project_number": "123456789012", "project_id": "demo-project", "storage_bucket": "demo-project.firebasestorage.app"},
          "client": [
            {
              "client_info": {"mobilesdk_app_id": "1:123456789012:android:aaaa", "android_client_info": {"package_name": "io.passauth.app"}},
              "oauth_client": [],
              "api_key": [{"current_key": "test-key-release"}],
              "services": {"appinvite_service": {"other_platform_oauth_client": []}}
            },
            {
              "client_info": {"mobilesdk_app_id": "1:123456789012:android:bbbb", "android_client_info": {"package_name": "io.passauth.app.debug"}},
              "oauth_client": [],
              "api_key": [{"current_key": "test-key-debug"}],
              "services": {"appinvite_service": {"other_platform_oauth_client": []}}
            }
          ],
          "configuration_version": "1"
        }
    """.trimIndent()

    @Test
    fun picksTheClientOfTheVariantsApplicationId() {
        assertEquals(
            FirebaseClientConfig("1:123456789012:android:aaaa", "test-key-release", "demo-project", "123456789012"),
            FirebaseClientConfig.parse(json, "io.passauth.app"),
        )
        assertEquals(
            FirebaseClientConfig("1:123456789012:android:bbbb", "test-key-debug", "demo-project", "123456789012"),
            FirebaseClientConfig.parse(json, "io.passauth.app.debug"),
        )
    }

    @Test
    fun noMatchingClientOrBrokenFileGivesNothing() {
        assertNull(FirebaseClientConfig.parse(json, "io.passauth.other"))
        assertNull(FirebaseClientConfig.parse("", "io.passauth.app"))
        assertNull(FirebaseClientConfig.parse("{", "io.passauth.app"))
        assertNull(FirebaseClientConfig.parse(json.dropLast(1), "io.passauth.app"))
        assertNull(FirebaseClientConfig.parse("""{"client": []}""", "io.passauth.app"))
        // A client without an API key.
        assertNull(FirebaseClientConfig.parse(json.replace("\"test-key-release\"", "\"\""), "io.passauth.app"))
        assertNull(FirebaseClientConfig.parse(json.replace("[{\"current_key\": \"test-key-release\"}]", "[]"), "io.passauth.app"))
    }

    @Test
    fun readsEscapesAndWritesJavaLiterals() {
        val escaped = json.replace("demo-project\"", "demo\\u002dproject\"")
        assertEquals("demo-project", FirebaseClientConfig.parse(escaped, "io.passauth.app")?.projectId)
        assertEquals("\"a\\\"b\\\\c\"", FirebaseClientConfig.literal("a\"b\\c"))
        assertEquals("\"\"", FirebaseClientConfig.literal(""))
    }

    @Test
    fun neverPrintsTheKey() {
        val c = FirebaseClientConfig.parse(json, "io.passauth.app")!!
        assertEquals(false, c.toString().contains("test-key"))
    }
}
