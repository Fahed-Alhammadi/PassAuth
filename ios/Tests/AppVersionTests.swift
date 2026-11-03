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

    /// The built app carries ios/VERSION (scripts/version.sh → Version.xcconfig → Info.plist).
    func testAppBundleMatchesVersionFile() throws {
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../VERSION")
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { throw XCTSkip("ios/VERSION not readable from the simulator") }
        let v = try AppVersion.of(text.trimmingCharacters(in: .whitespacesAndNewlines))
        let info = Bundle.main.infoDictionary ?? [:]
        XCTAssertEqual(info["CFBundleShortVersionString"] as? String, v.name)
        XCTAssertEqual(info["CFBundleVersion"] as? String, String(v.code))
    }
}
