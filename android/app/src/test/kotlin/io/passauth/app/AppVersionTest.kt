package io.passauth.app

import AppVersion
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AppVersionTest {
    @Test
    fun versionCodeFromSemver() {
        assertEquals(3_003, AppVersion.of("0.3.3").code)
        assertEquals(1_000_000, AppVersion.of("1.0.0").code)
        assertEquals(12_345_678, AppVersion.of("12.345.678").code)
        assertEquals(2_000_999, AppVersion.of("2.0.999").code)
    }

    @Test
    fun codesIncreaseWithVersions() {
        val ordered = listOf("0.3.3", "0.3.4", "0.4.0", "0.10.0", "1.0.0", "1.0.1", "2.0.0")
        val codes = ordered.map { AppVersion.of(it).code }
        assertEquals(codes.sorted(), codes)
    }

    @Test
    fun rejectsInvalidVersions() {
        assertThrows(IllegalStateException::class.java) { AppVersion.of("1.2") }
        assertThrows(IllegalStateException::class.java) { AppVersion.of("1.2.3-beta") }
        assertThrows(IllegalArgumentException::class.java) { AppVersion.of("1.1000.0") }
    }

    @Test
    fun readsWorkspacePackageVersion() {
        val toml = """
            [workspace]
            members = ["crates/*"]

            [package]
            version = "9.9.9"

            [workspace.package]
            edition = "2024"
            version = "0.3.3" # bumped on release
            license = "MIT"

            [workspace.dependencies]
            version = "1.0.0"
        """.trimIndent()
        assertEquals(AppVersion("0.3.3", 3_003), AppVersion.fromCargoToml(toml))
    }

    @Test
    fun repositoryCargoTomlHasAValidVersion() {
        val cargo = generateSequence(File("").absoluteFile) { it.parentFile }.map { File(it, "Cargo.toml") }.firstOrNull { it.exists() }
            ?: return
        val v = AppVersion.fromCargoToml(cargo.readText())
        assertTrue(v.code > 0)
    }
}
