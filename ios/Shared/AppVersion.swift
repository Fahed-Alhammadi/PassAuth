import Foundation

/// App version from `ios/VERSION` (the iOS app's own version, independent of the server),
/// written into Version.xcconfig by `ios/scripts/version.sh`. Build number = major·1 000 000 + minor·1 000 + patch
/// (0.3.3 → 3003), as Android's versionCode. This type mirrors the script for tests.
public struct AppVersion: Equatable, Sendable {
    public let name: String
    public let code: Int

    public init(name: String, code: Int) {
        self.name = name
        self.code = code
    }

    public enum Problem: Error, Equatable { case notSemver, outOfRange }

    public static func of(_ name: String) throws -> AppVersion {
        let n = name.trimmingCharacters(in: .whitespaces)
        let parts = n.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }),
              let major = Int(parts[0]), let minor = Int(parts[1]), let patch = Int(parts[2])
        else { throw Problem.notSemver }
        guard minor < 1000, patch < 1000, major < 2100 else { throw Problem.outOfRange }
        return AppVersion(name: n, code: major * 1_000_000 + minor * 1_000 + patch)
    }


    /// This build's version (Info.plist).
    public static var current: (name: String, build: String) {
        let info = Bundle.main.infoDictionary ?? [:]
        return (info["CFBundleShortVersionString"] as? String ?? "", info["CFBundleVersion"] as? String ?? "")
    }
}
