import PassAuthKit
import XCTest

/// The app's wrappers over the core's site logic (`UrlMatcher`): its item types and settings
/// reach the core as they should (every match type, the default match setting, the shared-vault
/// regex rule), and its own URL reading (`parse`, for display and the server address). The
/// matching rules themselves are pinned by the golden vectors (GoldenVectorTests).
final class UrlMatcherTests: XCTestCase {
    private func m(_ page: String, _ url: String, _ match: UrlMatch, _ fallback: UrlMatch = .domain, allowRegex: Bool = true) -> Bool {
        UrlMatcher.matches(page, LoginUrl(url: url, match: match), fallback: fallback, allowRegex: allowRegex)
    }

    func testEveryMatchTypeReachesTheCore() {
        XCTAssertTrue(m("https://login.example.com/a", "https://www.example.com", .domain))
        XCTAssertFalse(m("https://www.example.com", "https://login.example.com", .host))
        XCTAssertTrue(m("https://example.com/app/login", "https://example.com/app", .startsWith))
        XCTAssertFalse(m("https://example.com/other", "https://example.com/app", .startsWith))
        XCTAssertTrue(m("https://example.com", "https://example.com/", .exact))
        XCTAssertTrue(m("https://Accounts.Example.com/signin", "^https://accounts\\.example\\.com/", .regex))
        XCTAssertFalse(m("https://example.com", "https://example.com", .never))
        XCTAssertFalse(m("https://nas.myfritz.net", "https://evil.myfritz.net", .domain), "the full Public Suffix List")
    }

    func testDefaultFollowsTheSetting() {
        XCTAssertTrue(m("https://a.example.com", "https://b.example.com", .default, .domain))
        XCTAssertFalse(m("https://a.example.com", "https://b.example.com", .default, .host))
        XCTAssertFalse(m("https://example.com", "https://example.com", .default, .never))
        XCTAssertTrue(m("https://example.com/x", "^https://example\\.com/", .default, .regex))
    }

    func testRegularExpressionsOnlyForTheUsersOwnLogins() {
        XCTAssertFalse(m("https://example.com/", ".*", .regex, allowRegex: false))
        XCTAssertFalse(m("https://example.com/", ".*", .default, .regex, allowRegex: false))
        XCTAssertTrue(m("https://www.example.com/", "https://example.com", .domain, allowRegex: false), "a shared login's other websites match")
        let login = Login(username: "", password: "", urls: [LoginUrl(url: ".*", match: .regex), LoginUrl(url: "https://example.org", match: .domain)])
        XCTAssertFalse(UrlMatcher.matchesAny("https://example.com/", login, allowRegex: false))
        XCTAssertTrue(UrlMatcher.matchesAny("https://example.com/", login, allowRegex: true))
        XCTAssertTrue(UrlMatcher.matchesAny("https://www.example.org/", login, allowRegex: false))
        XCTAssertFalse(UrlMatcher.matchesAny("https://example.com/", Login(username: "", password: "", urls: [])))
    }

    func testAppAddressesAndOtherPagesNeverMatch() {
        XCTAssertFalse(m("https://example.com/", "androidapp://example.com", .domain))
        XCTAssertFalse(m("ftp://example.com", "https://example.com", .domain))
        XCTAssertFalse(m("not a url", "https://example.com", .domain))
    }

    func testDowngradeAndRegexErrors() {
        XCTAssertTrue(UrlMatcher.downgrade("http://example.com", LoginUrl(url: "https://example.com", match: .domain)))
        XCTAssertFalse(UrlMatcher.downgrade("http://localhost:8080", LoginUrl(url: "https://localhost", match: .host)))
        XCTAssertTrue(UrlMatcher.downgrade("http://example.com/", LoginUrl(url: "^https://example", match: .regex)))
        XCTAssertNil(UrlMatcher.regexError("^https://(www\\.)?example\\.com/"))
        XCTAssertNil(UrlMatcher.regexError("(a+)+$"), "linear time: nothing is refused for being slow")
        XCTAssertEqual(UrlMatcher.regexError("(?<=a)b"), "Look-around is not supported.")
        XCTAssertNotNil(UrlMatcher.regexError(String(repeating: "x", count: 301)))
    }

    /// Core review M2: the item editor's note under a website that runs as a regular expression
    /// (`resolveMatch` is "regex"): the core's refusal, or the warning that it isn't tied to one
    /// website. Never for other match types, nor for a plain address under the regex default.
    func testPatternNoteInTheEditor() {
        let note = { (url: String, match: UrlMatch, fallback: UrlMatch) in UrlMatcher.patternNote(url: url, match: match, defaultMatch: fallback) }
        XCTAssertEqual(note("bank\\.com", .regex, .domain), .warning, "unanchored: matches https://evil.com/bank.com too")
        XCTAssertEqual(note(".*", .regex, .domain), .warning)
        XCTAssertEqual(note("^https://.*bank\\.com/", .regex, .domain), .warning, "host not pinned")
        XCTAssertNil(note("^https://bank\\.com/", .regex, .domain), "tied to its website")
        XCTAssertEqual(note("(?<=a)b", .regex, .domain), .error("Look-around is not supported."))
        // "Default" under the regular-expression setting: a pattern is a pattern…
        XCTAssertEqual(note("bank\\.com", .default, .regex), .warning)
        XCTAssertNil(note("^https://bank\\.com/", .default, .regex))
        // …but a plain address is matched by its domain there (no note).
        XCTAssertNil(note("https://bank.com", .default, .regex))
        // Other match types and blank entries: nothing.
        for m in [UrlMatch.domain, .host, .startsWith, .exact, .never] { XCTAssertNil(note("bank\\.com", m, .regex)) }
        XCTAssertNil(note("bank\\.com", .default, .domain))
        XCTAssertNil(note("   ", .regex, .domain))
        XCTAssertEqual(UrlMatcher.patternWarning,
                       "This pattern isn't tied to one website, so it could match other sites. Start it with ^https://example\\.com/ (your site's address).")
    }

    func testBaseDomain() {
        XCTAssertEqual(UrlMatcher.baseDomain("login.example.co.uk"), "example.co.uk")
        XCTAssertEqual(UrlMatcher.baseDomain("Example.COM."), "example.com")
        XCTAssertEqual(UrlMatcher.baseDomain("x.nas.myfritz.net"), "nas.myfritz.net")
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
        // Internationalised names through the core's host parser (UTS #46 nontransitional).
        XCTAssertEqual(UrlMatcher.parse("https://straße.de/login")?.hostname, "xn--strae-oqa.de")
        XCTAssertEqual(UrlMatcher.parse("BÜCHER.de:8443")?.host, "xn--bcher-kva.de:8443")
        XCTAssertNil(UrlMatcher.parse("https://bü<cher.de"))
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
