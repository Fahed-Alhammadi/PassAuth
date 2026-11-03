/**
 * App version from `android/VERSION` (the Android app's own version, independent of the
 * server; bump it with `scripts/release.sh android X.Y.Z`).
 *
 * versionCode = major * 1_000_000 + minor * 1_000 + patch (0.3.3 -> 3_003).
 *
 * Shared by the Gradle build (buildSrc) and the app's unit tests; keep it plain Kotlin.
 */
data class AppVersion(val name: String, val code: Int) {
    companion object {
        private val SEMVER = Regex("""^(\d+)\.(\d+)\.(\d+)$""")

        fun of(name: String): AppVersion {
            val m = SEMVER.matchEntire(name.trim()) ?: error("Version must be X.Y.Z, got \"$name\"")
            val (major, minor, patch) = m.destructured.toList().map { it.toInt() }
            require(minor < 1000 && patch < 1000) { "Minor and patch must be below 1000: $name" }
            require(major < 2100) { "Major version too large for a versionCode: $name" }
            return AppVersion(name.trim(), major * 1_000_000 + minor * 1_000 + patch)
        }

        /** Reads the contents of a VERSION file (one X.Y.Z line). */
        fun fromVersionFile(text: String): AppVersion = of(text.trim())
    }
}
