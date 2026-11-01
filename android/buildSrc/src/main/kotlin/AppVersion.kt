/**
 * App version, derived from the Rust workspace version in the root `Cargo.toml`
 * (`[workspace.package] version`), so the app ships with the same number as the server.
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

        /** Reads `version` from the `[workspace.package]` table of a Cargo.toml. */
        fun fromCargoToml(text: String): AppVersion {
            var inSection = false
            for (raw in text.lineSequence()) {
                val line = raw.substringBefore('#').trim()
                if (line.startsWith("[")) {
                    inSection = line == "[workspace.package]"
                    continue
                }
                if (!inSection) continue
                val m = Regex("""^version\s*=\s*"([^"]+)"$""").matchEntire(line) ?: continue
                return of(m.groupValues[1])
            }
            error("No [workspace.package] version in Cargo.toml")
        }
    }
}
