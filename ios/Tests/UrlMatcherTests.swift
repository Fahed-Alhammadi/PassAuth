import PassAuthKit
import XCTest

/// Same cases as the extension's urls.ts semantics (and the Android UrlMatcherTest).
final class UrlMatcherTests: XCTestCase {
    private func m(_ page: String, _ url: String, _ match: UrlMatch, _ fallback: UrlMatch = .domain) -> Bool {
        UrlMatcher.matches(page, LoginUrl(url: url, match: match), fallback: fallback)
    }

    func testBaseDomain() {
        XCTAssertEqual(UrlMatcher.baseDomain("login.example.com"), "example.com")
        XCTAssertEqual(UrlMatcher.baseDomain("Example.COM."), "example.com")
        XCTAssertEqual(UrlMatcher.baseDomain("www.example.co.uk"), "example.co.uk")
        XCTAssertEqual(UrlMatcher.baseDomain("co.uk"), "co.uk")
        XCTAssertEqual(UrlMatcher.baseDomain("a.me.github.io"), "me.github.io")
        XCTAssertEqual(UrlMatcher.baseDomain("192.168.1.10"), "192.168.1.10")
        XCTAssertEqual(UrlMatcher.baseDomain("localhost"), "localhost")
        XCTAssertEqual(UrlMatcher.baseDomain("[::1]"), "[::1]")
    }

    func testParseNormalisesLikeTheBrowser() throws {
        let p = try XCTUnwrap(UrlMatcher.parse("HTTPS://Example.com:443"))
        XCTAssertEqual(p.scheme, "https")
        XCTAssertEqual(p.host, "example.com")
        XCTAssertEqual(p.href, "https://example.com/")
        XCTAssertEqual(UrlMatcher.parse("example.com:8443/x")?.host, "example.com:8443")
        XCTAssertEqual(UrlMatcher.parse("example.com/login?a=1#f")?.href, "https://example.com/login?a=1#f")
        XCTAssertNil(UrlMatcher.parse("https://exa mple.com"))
    }

    func testDomainMatch() {
        XCTAssertTrue(m("https://login.example.com/a", "https://www.example.com", .domain))
        XCTAssertTrue(m("https://example.com", "example.com", .domain))
        XCTAssertFalse(m("https://example.org", "https://example.com", .domain))
        XCTAssertFalse(m("https://a.co.uk", "https://b.co.uk", .domain))
        XCTAssertFalse(m("https://evil-example.com", "https://example.com", .domain))
    }

    func testHostMatchIncludesPort() {
        XCTAssertTrue(m("https://login.example.com/x", "https://login.example.com", .host))
        XCTAssertFalse(m("https://www.example.com", "https://login.example.com", .host))
        XCTAssertFalse(m("https://example.com:8443", "https://example.com", .host))
        XCTAssertTrue(m("https://example.com:443/", "https://example.com", .host))
    }

    func testStartsWithAndExact() {
        XCTAssertTrue(m("https://example.com/app/login", "https://example.com/app", .startsWith))
        XCTAssertFalse(m("https://example.com/other", "https://example.com/app", .startsWith))
        XCTAssertTrue(m("https://example.com", "https://example.com/", .exact))
        XCTAssertFalse(m("https://example.com/login", "https://example.com/", .exact))
    }

    func testRegexAndNever() {
        XCTAssertTrue(m("https://Accounts.Example.com/signin", "^https://accounts\\.example\\.com/", .regex))
        XCTAssertFalse(m("https://example.com", "(", .regex))
        XCTAssertFalse(m("https://example.com", "https://example.com", .never))
    }

    func testDefaultFollowsTheSetting() {
        XCTAssertTrue(m("https://a.example.com", "https://b.example.com", .default, .domain))
        XCTAssertFalse(m("https://a.example.com", "https://b.example.com", .default, .host))
        XCTAssertFalse(m("https://example.com", "https://example.com", .default, .never))
    }

    func testOnlyWebPagesMatch() {
        XCTAssertFalse(m("ftp://example.com", "https://example.com", .domain))
        XCTAssertFalse(m("not a url", "https://example.com", .domain))
    }

    func testDowngrade() {
        XCTAssertTrue(UrlMatcher.downgrade("http://example.com", LoginUrl(url: "https://example.com", match: .domain)))
        XCTAssertFalse(UrlMatcher.downgrade("https://example.com", LoginUrl(url: "https://example.com", match: .domain)))
        XCTAssertFalse(UrlMatcher.downgrade("http://localhost:8080", LoginUrl(url: "https://localhost", match: .host)))
        XCTAssertTrue(UrlMatcher.downgrade("http://example.com/", LoginUrl(url: "^https://example", match: .regex)))
        XCTAssertFalse(UrlMatcher.downgrade("http://localhost/x", LoginUrl(url: "^https://localhost", match: .regex)))
    }

    func testServerAddressPolicy() throws {
        XCTAssertEqual(try VaultRepository.normalizeServer(" https://Vault.Example.com/ "), "https://vault.example.com")
        XCTAssertEqual(try VaultRepository.normalizeServer("vault.example.com/pa/"), "https://vault.example.com/pa")
        XCTAssertEqual(try VaultRepository.normalizeServer("http://127.0.0.1:8091"), "http://127.0.0.1:8091")
        XCTAssertEqual(try VaultRepository.normalizeServer("http://localhost:8080"), "http://localhost:8080")
        XCTAssertEqual(try VaultRepository.normalizeServer("http://192.168.1.20:8080"), "http://192.168.1.20:8080")
        XCTAssertEqual(try VaultRepository.normalizeServer("http://nas.local"), "http://nas.local")
        XCTAssertThrowsError(try VaultRepository.normalizeServer("http://vault.example.com"))
        XCTAssertThrowsError(try VaultRepository.normalizeServer("http://8.8.8.8"))
        XCTAssertThrowsError(try VaultRepository.normalizeServer("http://172.32.0.1"))
        XCTAssertThrowsError(try VaultRepository.normalizeServer(""))
    }
}
