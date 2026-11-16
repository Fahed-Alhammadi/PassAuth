import PassAuthCore
import PassAuthKit
import XCTest

/// Send rules: the owner's cases of the web vault's `web/src/lib/sends.test.ts`, plus the core
/// round trip the app relies on.
final class SendsTests: XCTestCase {
    private let id = "AbCdEfGhIjKlMnOpQrSt_-"
    private let key = String(repeating: "k", count: 40) + "_-A"

    func testBuildsTheLinkWithTheKeyAfterTheHash() {
        XCTAssertEqual(SendRules.link(origin: "https://vault.example.com", id: id, key: key), "https://vault.example.com/send/\(id)#\(key)")
        XCTAssertEqual(SendRules.link(origin: "https://vault.example.com/", id: id, key: key), "https://vault.example.com/send/\(id)#\(key)")
    }

    func testHidesTheKeyWhenTheLinkIsShownNeverAnythingBeforeIt() {
        let link = SendRules.link(origin: "https://vault.example.com", id: id, key: key)
        let masked = SendRules.masked(link)
        XCTAssertTrue(masked.hasPrefix("https://vault.example.com/send/\(id)#"))
        XCTAssertFalse(masked.contains(key))
        XCTAssertFalse(masked.contains(String(key.prefix(4))))
        XCTAssertEqual(SendRules.masked("https://vault.example.com/send/x"), "https://vault.example.com/send/x")
    }

    func testMeasuresTheEncryptedTextAsTheServerDoes() {
        XCTAssertEqual(SendRules.encryptedFieldLength(0), Int((Double(41 * 4) / 3).rounded(.up)))
        XCTAssertEqual(SendRules.encryptedFieldLength(5), Int((Double(46 * 4) / 3).rounded(.up)))
        XCTAssertEqual(SendRules.utf8Length("héllo"), 6)
    }

    func testKnowsTheMostTextThatFits() {
        let max = SendRules.maxTextBytes(SendRules.defaultMaxBytes)
        XCTAssertLessThanOrEqual(SendRules.encryptedFieldLength(max), SendRules.defaultMaxBytes)
        XCTAssertGreaterThan(SendRules.encryptedFieldLength(max + 1), SendRules.defaultMaxBytes)
        XCTAssertEqual(SendRules.maxTextBytes(10), 0)
    }

    func testReadsTheLimitsFromConfigElseTheServersDefaults() {
        XCTAssertTrue(SendRules.limits(["send_max_days": 7, "send_max_bytes": 2048]) == (7, 2048))
        XCTAssertTrue(SendRules.limits(nil) == (30, SendRules.defaultMaxBytes))
        XCTAssertTrue(SendRules.limits(["send_max_days": 0, "send_max_bytes": "x"]) == (30, SendRules.defaultMaxBytes))
    }

    func testCraftedLimitsAndNumbersDontCrash() throws {
        let l = SendRules.limits(try JSON.parse(#"{"send_max_days":1e300,"send_max_bytes":9223372036854775807}"#))
        XCTAssertEqual(l.maxDays, 36_500)
        XCTAssertEqual(l.maxBytes, 1 << 40)
        XCTAssertGreaterThan(SendRules.maxTextBytes(l.maxBytes), 0)
        XCTAssertFalse(SendRules.durationChoices(l.maxDays).isEmpty)
        XCTAssertTrue(SendRules.limits(try JSON.parse(#"{"send_max_days":-1e300,"send_max_bytes":1e300}"#)) == (30, 1 << 40))
        var crafted = raw
        crafted["max_views"] = .double(1e300)
        crafted["expires_at"] = .double(-1e300)
        crafted["delete_at"] = .double(.infinity)
        crafted["created_at"] = .double(9.9e18)
        _ = OwnedSend(json: .object(crafted))
    }

    func testOffersWhatTheServerAllowsAndItsLimit() {
        XCTAssertEqual(SendRules.durationChoices(30).map(\.label), ["1 hour", "1 day", "2 days", "3 days", "7 days", "14 days", "30 days"])
        XCTAssertEqual(SendRules.durationChoices(10).map(\.label), ["1 hour", "1 day", "2 days", "3 days", "7 days", "10 days"])
        XCTAssertEqual(SendRules.durationChoices(1).map(\.label), ["1 hour", "1 day"])
        XCTAssertEqual(SendRules.durationChoices(365).last?.seconds, 365 * 86400)
        XCTAssertEqual(SendRules.durationChoices(365).last?.label, "365 days")
    }

    func testDeletesAfter7DaysByDefaultOrSoonerWhenTheServerSaysSo() {
        XCTAssertEqual(SendRules.defaultDeletion(30), 7 * 86400)
        XCTAssertEqual(SendRules.defaultDeletion(3), 3 * 86400)
    }

    private var raw: [String: JSON] {
        [
            "id": .string(id), "path": .string("/send/\(id)"), "kind": "text", "name": "enc-name", "owner_key": "wrapped", "size": 100,
            "has_password": true, "access_salt": "sendpw-v1$m=131072,t=3,p=1$abc", "max_views": 5, "views": 2, "expires_at": 2000,
            "delete_at": 3000, "disabled": false, "hide_email": true, "available": true, "created_at": 100, "updated_at": 200,
        ]
    }

    func testReadsTheOwnersSends() throws {
        let s = try XCTUnwrap(OwnedSend(json: .object(raw)))
        XCTAssertEqual(s.id, id)
        XCTAssertEqual(s.name, "enc-name")
        XCTAssertEqual(s.ownerKey, "wrapped")
        XCTAssertTrue(s.hasPassword)
        XCTAssertEqual(s.maxViews, 5)
        XCTAssertEqual(s.views, 2)
        XCTAssertEqual(s.expiresAt, 2000)
        XCTAssertEqual(s.deleteAt, 3000)
        XCTAssertTrue(s.hideEmail)
        XCTAssertNil(s.data)
        var withData = raw
        withData["data"] = "enc-text"
        XCTAssertEqual(OwnedSend(json: .object(withData))?.data, "enc-text")
        XCTAssertEqual(OwnedSend.list(["sends": [.object(raw), ["id": "x"], nil]]).count, 1)
        XCTAssertEqual(OwnedSend.list([:]), [])
    }

    func testSaysWhetherTheyCanBeOpened() throws {
        let s = try XCTUnwrap(OwnedSend(json: .object(raw)))
        XCTAssertEqual(s.state(now: 1000), .available)
        var d = s
        d.disabled = true
        XCTAssertEqual(d.state(now: 1000), .disabled)
        XCTAssertEqual(s.state(now: 2000), .expired)
        var used = s
        used.views = 5
        XCTAssertEqual(used.state(now: 1000), .usedUp)
        XCTAssertEqual(s.state(now: 3000), .deleted)
        var off = s
        off.available = false
        XCTAssertEqual(off.state(now: 1000), .unavailable)
    }

    func testCountsViews() {
        XCTAssertEqual(OwnedSend.viewsText(views: 0, maxViews: nil), "Not opened yet")
        XCTAssertEqual(OwnedSend.viewsText(views: 1, maxViews: nil), "Opened 1 time")
        XCTAssertEqual(OwnedSend.viewsText(views: 2, maxViews: 5), "Opened 2 of 5 times")
        XCTAssertEqual(OwnedSend.viewsText(views: 0, maxViews: 1), "Opened 0 of 1 time")
    }

    func testSendsOnlyWhatChanged() {
        XCTAssertEqual(SendChanges().body, [:])
        var a = SendChanges()
        a.name = "n"
        a.disabled = true
        XCTAssertEqual(a.body, ["name": "n", "disabled": true])
        var b = SendChanges()
        b.password = .set(salt: "s", verifier: "v")
        XCTAssertEqual(b.body, ["access_salt": "s", "access_verifier": "v"])
        var c = SendChanges()
        c.password = .remove
        c.maxViews = .set(nil)
        c.expiresAt = .set(nil)
        XCTAssertEqual(c.body, ["access_verifier": nil, "max_views": nil, "expires_at": nil])
        var d = SendChanges()
        d.deleteAt = 5
        d.hideEmail = false
        d.data = "d"
        XCTAssertEqual(d.body, ["delete_at": 5, "hide_email": false, "data": "d"])
    }

    /// The core's send key: the link carries it, the name and text open only with it and the field.
    func testCoreRoundTrip() throws {
        let key = try sendNewKey()
        XCTAssertEqual(key.count, 43)
        let enc = try sendEncrypt(key: key, field: "data", plaintext: "hello")
        XCTAssertEqual(try sendDecrypt(key: key, field: "data", ciphertext: enc), "hello")
        XCTAssertThrowsError(try sendDecrypt(key: key, field: "name", ciphertext: enc))
        XCTAssertEqual(enc.count, SendRules.encryptedFieldLength(5))
    }
}
