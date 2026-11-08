import PassAuthKit
import XCTest

/// The macOS AutoFill extension's vault timeout (`TimedUnlockPolicy`, compiled into this bundle).
final class TimedUnlockPolicyTests: XCTestCase {
    func testKeepSeconds() {
        XCTAssertNil(TimedUnlockPolicy.keepSeconds(.immediately))
        XCTAssertNil(TimedUnlockPolicy.keepSeconds(.never)) // kept by the repository itself
        XCTAssertNil(TimedUnlockPolicy.keepSeconds(.restart))
        XCTAssertEqual(TimedUnlockPolicy.keepSeconds(.min1), 60)
        XCTAssertEqual(TimedUnlockPolicy.keepSeconds(.min15), 900)
        XCTAssertEqual(TimedUnlockPolicy.keepSeconds(.hour4), 14_400)
    }

    func testChoicesLeaveOutAppRestart() {
        XCTAssertFalse(TimedUnlockPolicy.choices.contains(.restart))
        XCTAssertEqual(TimedUnlockPolicy.choices.first, .immediately)
        XCTAssertEqual(TimedUnlockPolicy.choices.last, .never)
    }

    func testRecord() {
        XCTAssertNil(TimedUnlockPolicy.record(account: "a", keys: "k", timeout: .immediately, now: 100))
        XCTAssertNil(TimedUnlockPolicy.record(account: "", keys: "k", timeout: .min5, now: 100))
        XCTAssertNil(TimedUnlockPolicy.record(account: "a", keys: "", timeout: .min5, now: 100))
        XCTAssertEqual(TimedUnlockPolicy.record(account: "a", keys: "k", timeout: .min5, now: 100),
                       .init(account: "a", until: 400, keys: "k"))
    }

    func testUsableWithinTimeoutOnly() {
        let r = TimedUnlockPolicy.Record(account: "a", until: 1_000, keys: "k")
        XCTAssertTrue(TimedUnlockPolicy.usable(r, account: "a", timeout: .min15, now: 999))
        XCTAssertFalse(TimedUnlockPolicy.usable(r, account: "a", timeout: .min15, now: 1_000)) // deadline passed
        XCTAssertFalse(TimedUnlockPolicy.usable(r, account: "b", timeout: .min15, now: 999)) // other account
        XCTAssertFalse(TimedUnlockPolicy.usable(r, account: "a", timeout: .immediately, now: 999))
        XCTAssertFalse(TimedUnlockPolicy.usable(r, account: "a", timeout: .never, now: 999))
    }

    func testShortenedTimeoutRejectsOlderDeadline() {
        // Kept for 1 hour, then the user picked 1 minute: the far deadline no longer counts.
        let r = TimedUnlockPolicy.record(account: "a", keys: "k", timeout: .hour1, now: 0)!
        XCTAssertTrue(TimedUnlockPolicy.usable(r, account: "a", timeout: .hour1, now: 10))
        XCTAssertFalse(TimedUnlockPolicy.usable(r, account: "a", timeout: .min1, now: 10))
        XCTAssertTrue(TimedUnlockPolicy.usable(r, account: "a", timeout: .min1, now: 3_550))
    }

    func testStaleFromDeadlineAlone() {
        XCTAssertTrue(TimedUnlockPolicy.stale(until: nil, timeout: .min15, now: 0)) // no readable deadline
        XCTAssertFalse(TimedUnlockPolicy.stale(until: 900, timeout: .min15, now: 0))
        XCTAssertTrue(TimedUnlockPolicy.stale(until: 900, timeout: .min15, now: 900)) // deadline reached
        XCTAssertTrue(TimedUnlockPolicy.stale(until: 900, timeout: .min15, now: 5_000))
        XCTAssertTrue(TimedUnlockPolicy.stale(until: 900, timeout: .min1, now: 0)) // timeout shortened
        XCTAssertTrue(TimedUnlockPolicy.stale(until: 900, timeout: .immediately, now: 0))
        XCTAssertTrue(TimedUnlockPolicy.stale(until: 900, timeout: .never, now: 0))
    }

    func testRecordRoundTrip() throws {
        let r = TimedUnlockPolicy.Record(account: "a", until: 5, keys: "AAEC")
        let back = try JSONDecoder().decode(TimedUnlockPolicy.Record.self, from: JSONEncoder().encode(r))
        XCTAssertEqual(back, r)
    }
}
