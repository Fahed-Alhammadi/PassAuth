import Foundation

/// App version, derived from the Rust workspace version in the root `Cargo.toml`
/// (`[workspace.package] version`) by `ios/scripts/version.sh`, so the app ships with the
/// same number as the server. Build number = major·1 000 000 + minor·1 000 + patch
/// (0.3.3 → 3003), as Android's versionCode. This type mirrors the script for tests.
public struct AppVersion: Equatable, Sendable {
    public let name: String
    public let code: Int

    public init(name: String, code: Int) {
        self.name = name
        self.code = code
    }

    public enum Problem: Error, Equatable { case notSemver, outOfRange, missing }

    public static func of(_ name: String) throws -> AppVersion {
        let n = name.trimmingCharacters(in: .whitespaces)
        let parts = n.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }),
              let major = Int(parts[0]), let minor = Int(parts[1]), let patch = Int(parts[2])
        else { throw Problem.notSemver }
        guard minor < 1000, patch < 1000, major < 2100 else { throw Problem.outOfRange }
        return AppVersion(name: n, code: major * 1_000_000 + minor * 1_000 + patch)
    }

    /// Reads `version` from the `[workspace.package]` table of a Cargo.toml.
    public static func fromCargoToml(_ text: String) throws -> AppVersion {
        var inSection = false
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = (raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
                .trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") {
                inSection = line == "[workspace.package]"
                continue
            }
            guard inSection, line.hasPrefix("version") else { continue }
            let value = line.dropFirst("version".count).trimmingCharacters(in: .whitespaces)
            guard value.hasPrefix("=") else { continue }
            let v = value.dropFirst().trimmingCharacters(in: .whitespaces)
            guard v.count >= 2, v.hasPrefix("\""), v.hasSuffix("\"") else { continue }
            return try of(String(v.dropFirst().dropLast()))
        }
        throw Problem.missing
    }

    /// This build's version (Info.plist).
    public static var current: (name: String, build: String) {
        let info = Bundle.main.infoDictionary ?? [:]
        return (info["CFBundleShortVersionString"] as? String ?? "", info["CFBundleVersion"] as? String ?? "")
    }
}
