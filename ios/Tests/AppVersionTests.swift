import PassAuthKit
import XCTest

final class AppVersionTests: XCTestCase {
    func testBuildNumberFromSemver() throws {
        XCTAssertEqual(try AppVersion.of("0.3.3").code, 3_003)
        XCTAssertEqual(try AppVersion.of("1.0.0").code, 1_000_000)
        XCTAssertEqual(try AppVersion.of("12.345.678").code, 12_345_678)
        XCTAssertEqual(try AppVersion.of("2.0.999").code, 2_000_999)
    }

    func testCodesIncreaseWithVersions() throws {
        let codes = try ["0.3.3", "0.3.4", "0.4.0", "0.10.0", "1.0.0", "1.0.1", "2.0.0"].map { try AppVersion.of($0).code }
        XCTAssertEqual(codes, codes.sorted())
    }

    func testRejectsInvalidVersions() {
        XCTAssertThrowsError(try AppVersion.of("1.2"))
        XCTAssertThrowsError(try AppVersion.of("1.2.3-beta"))
        XCTAssertThrowsError(try AppVersion.of("1.1000.0"))
    }

    func testReadsWorkspacePackageVersion() throws {
        let toml = """
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
        """
        XCTAssertEqual(try AppVersion.fromCargoToml(toml), AppVersion(name: "0.3.3", code: 3_003))
    }

    /// The built app carries the repository's version (scripts/version.sh → Version.xcconfig → Info.plist).
    func testAppBundleMatchesCargoToml() throws {
        let cargo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../Cargo.toml")
        guard let text = try? String(contentsOf: cargo, encoding: .utf8) else { throw XCTSkip("Cargo.toml not readable from the simulator") }
        let v = try AppVersion.fromCargoToml(text)
        let info = Bundle.main.infoDictionary ?? [:]
        XCTAssertEqual(info["CFBundleShortVersionString"] as? String, v.name)
        XCTAssertEqual(info["CFBundleVersion"] as? String, String(v.code))
    }
}
