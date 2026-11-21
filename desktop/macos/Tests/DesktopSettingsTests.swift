import PassAuthKit
import XCTest

/// AutoFill settings shared with the desktop app (`DesktopSettings`, compiled into this bundle).
final class DesktopSettingsTests: XCTestCase {
    private func json(_ s: String) -> Data { Data(s.utf8) }

    func testNewerChangeIsAdopted() {
        let a = DesktopSettings.adoption(json(#"{"defaultMatch":"host","changedAt":2000}"#), ownChangedAt: 1000)
        XCTAssertEqual(a, .init(match: .host, changedAt: 2000))
        XCTAssertEqual(DesktopSettings.adoption(json(#"{"defaultMatch":"starts_with","changedAt":5}"#), ownChangedAt: 0)?.match, .startsWith)
    }

    func testOlderOrSameChangeIsIgnored() {
        XCTAssertNil(DesktopSettings.adoption(json(#"{"defaultMatch":"host","changedAt":1000}"#), ownChangedAt: 1000))
        XCTAssertNil(DesktopSettings.adoption(json(#"{"defaultMatch":"host","changedAt":999}"#), ownChangedAt: 1000))
    }

    func testMissingMalformedOrUnknownIsIgnored() {
        XCTAssertNil(DesktopSettings.adoption(nil, ownChangedAt: 0))
        XCTAssertNil(DesktopSettings.adoption(json("not json"), ownChangedAt: 0))
        XCTAssertNil(DesktopSettings.adoption(json("{}"), ownChangedAt: 0))
        XCTAssertNil(DesktopSettings.adoption(json(#"{"defaultMatch":"host"}"#), ownChangedAt: 0))
        XCTAssertNil(DesktopSettings.adoption(json(#"{"defaultMatch":"default","changedAt":9}"#), ownChangedAt: 0))
        XCTAssertNil(DesktopSettings.adoption(json(#"{"defaultMatch":"sometimes","changedAt":9}"#), ownChangedAt: 0))
    }

    /// Every request reconciles: a newer desktop change is taken; a missing, unreadable or older item
    /// gets this extension's own value written back (the desktop shows what AutoFill really uses, also
    /// after the clock went back); the same change does nothing.
    func testReconcile() {
        let host = json(#"{"defaultMatch":"host","changedAt":2000}"#)
        XCTAssertEqual(DesktopSettings.reconcile(host, own: .exact, ownChangedAt: 1000), .adopt(.init(match: .host, changedAt: 2000)))
        XCTAssertEqual(DesktopSettings.reconcile(host, own: .exact, ownChangedAt: 3000), .publish(.exact, changedAt: 3000))
        XCTAssertEqual(DesktopSettings.reconcile(host, own: .host, ownChangedAt: 2000), .none)
        // Nothing written yet (an install from before this setting): the extension's value, never 0.
        XCTAssertEqual(DesktopSettings.reconcile(nil, own: .host, ownChangedAt: 0), .publish(.host, changedAt: 1))
        XCTAssertEqual(DesktopSettings.reconcile(json("garbage"), own: .domain, ownChangedAt: 7), .publish(.domain, changedAt: 7))
    }

    func testEncodesTheDesktopShape() throws {
        let data = DesktopSettings.encode(.startsWith, changedAt: 1_700_000_000_123)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["defaultMatch"] as? String, "starts_with")
        XCTAssertEqual((obj["changedAt"] as? NSNumber)?.int64Value, 1_700_000_000_123)
        XCTAssertEqual(DesktopSettings.adoption(data, ownChangedAt: 0), .init(match: .startsWith, changedAt: 1_700_000_000_123))
    }

    func testOldSettingsDecodeWithoutTheChangeTime() throws {
        let s = try JSONDecoder().decode(Settings.self, from: json(#"{"defaultMatch":"host"}"#))
        XCTAssertEqual(s.defaultMatch, .host)
        XCTAssertEqual(s.defaultMatchChangedAt, 0)
        let again = try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode({ var t = s; t.defaultMatchChangedAt = 42; return t }()))
        XCTAssertEqual(again.defaultMatchChangedAt, 42)
    }
}
