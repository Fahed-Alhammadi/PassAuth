import PassAuthKit
import XCTest

/// Site matching across tenants, bounded regex, where new items are saved and the plain-http
/// rule (same cases as the Android ReviewFixesTest and the extension's tests).
final class ReviewFixesTests: XCTestCase {
    private func m(_ page: String, _ url: String, _ match: UrlMatch) -> Bool {
        UrlMatcher.matches(page, LoginUrl(url: url, match: match), fallback: .domain)
    }

    func testDynamicDnsNamesAreSeparateSites() {
        XCTAssertEqual(UrlMatcher.baseDomain("nas.home.duckdns.org"), "home.duckdns.org")
        XCTAssertEqual(UrlMatcher.baseDomain("evil.duckdns.org"), "evil.duckdns.org")
        XCTAssertFalse(m("https://evil.duckdns.org/login", "https://home.duckdns.org", .domain))
        XCTAssertTrue(m("https://nas.home.duckdns.org/login", "https://home.duckdns.org", .domain))
        XCTAssertFalse(m("https://x.ddns.net", "https://y.ddns.net", .domain))
        XCTAssertEqual(UrlMatcher.baseDomain("api.app.up.railway.app"), "app.up.railway.app")
        XCTAssertEqual(UrlMatcher.baseDomain("duckdns.org"), "duckdns.org")
    }

    func testRegexIsBoundedAndIgnoresTheQuery() {
        XCTAssertFalse(m("https://evil.com/?bank.com", "bank\\.com", .regex))
        XCTAssertTrue(m("https://bank.com/login?x=1", "^https://bank\\.com/", .regex))
        XCTAssertTrue(UrlMatcher.unsafeRegex("(a+)+$"))
        XCTAssertTrue(UrlMatcher.unsafeRegex(String(repeating: "a", count: UrlMatcher.maxRegexLength + 1)))
        XCTAssertFalse(UrlMatcher.unsafeRegex("^https://accounts\\.example\\.com/"))
    }

    func testNewItemsGoToTheOwnVaultNeverASharedOne() {
        let planted = VaultInfo(id: "a", name: "Personal", role: .owner, keyKind: "sealed")
        let own = VaultInfo(id: "b", name: "My vault", role: .owner, keyKind: "account")
        XCTAssertEqual(VaultInfo.defaultSaveVault([planted, own]), own)
        XCTAssertNil(VaultInfo.defaultSaveVault([planted, VaultInfo(id: "c", name: "Team", role: .write, keyKind: "sealed")]))
        let ownWrite = VaultInfo(id: "d", name: "Mine", role: .write)
        XCTAssertEqual(VaultInfo.defaultSaveVault([planted, ownWrite]), ownWrite)
        XCTAssertNil(VaultInfo.defaultSaveVault([VaultInfo(id: "e", name: "Mine", role: .read)]))
    }

    func testPlainHttpOverTheNetworkNeedsConfirmation() {
        XCTAssertFalse(VaultRepository.plainHttpOnNetwork("http://127.0.0.1:8091"))
        XCTAssertFalse(VaultRepository.plainHttpOnNetwork("http://localhost:8080"))
        XCTAssertFalse(VaultRepository.plainHttpOnNetwork("https://192.168.1.20"))
        XCTAssertTrue(VaultRepository.plainHttpOnNetwork("http://192.168.1.20:8080"))
        XCTAssertTrue(VaultRepository.plainHttpOnNetwork("http://nas.local"))
    }
}
