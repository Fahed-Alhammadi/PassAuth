import PassAuthCore
import PassAuthKit
import XCTest

final class OtpAuthTests: XCTestCase {
    private func valid(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> OtpKey {
        guard let k = OtpAuth.parse(s).key else {
            XCTFail("expected valid: \(s) -> \(OtpAuth.parse(s))", file: file, line: line)
            return OtpKey(value: "")
        }
        return k
    }

    private func invalid(_ s: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotNil(OtpAuth.parse(s).problem, "expected invalid: \(s)", file: file, line: line)
    }

    func testOtpauthUriIsStoredWhole() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
        let k = valid(uri)
        XCTAssertEqual(k.value, uri)
        XCTAssertEqual(k.issuer, "Example")
        XCTAssertEqual(k.account, "alice@example.com")
        XCTAssertEqual(k.label, "Example (alice@example.com)")
    }

    func testUriLabelIsDecodedAndIssuerFallsBackToPrefix() {
        let k = valid("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
        XCTAssertEqual(k.issuer, "ACME Co")
        XCTAssertEqual(k.account, "john.doe@email.com")
    }

    func testUppercaseSchemeIsNormalisedForTheCore() {
        XCTAssertTrue(valid("OTPAUTH://TOTP/EX:BOB?SECRET=JBSWY3DPEHPK3PXP&ISSUER=EX").value.hasPrefix("otpauth://totp/EX:BOB?"))
    }

    func testUriParametersAreChecked() {
        _ = valid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11")
        invalid("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0")
        invalid("otpauth://totp/x?issuer=Nope")
        invalid("otpauth://totp/x?secret=not*base32")
    }

    func testUnsupportedKinds() {
        invalid("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")
        invalid("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8")
        invalid("https://example.com/2fa")
        invalid("")
        invalid("   ")
    }

    func testPlainBase32IsCleaned() {
        XCTAssertEqual(valid("jbsw y3dp ehpk 3pxp").value, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(valid("JBSW-Y3DP-EHPK-3PXP").value, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(valid("GEZDGNBV").value, "GEZDGNBV")
        XCTAssertEqual(valid("GEZDGNBV").label, "")
    }

    func testPlainBase32Errors() {
        invalid("JBSWY3DPEHPK3PX1")
        invalid("A")
        invalid("MZ")
    }

    func testBase32Decoding() {
        XCTAssertEqual(OtpAuth.decodeBase32("JBSWY3DPEHPK3PXP"), Array("Hello!".utf8) + [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(OtpAuth.decodeBase32("GEZDGNBV"), Array("12345".utf8))
        XCTAssertEqual(OtpAuth.decodeBase32("MY"), Array("f".utf8))
        XCTAssertNil(OtpAuth.decodeBase32(""))
    }

    func testUsableValues() {
        XCTAssertTrue(OtpAuth.isUsable(nil))
        XCTAssertTrue(OtpAuth.isUsable(""))
        XCTAssertTrue(OtpAuth.isUsable("JBSWY3DPEHPK3PXP"))
        XCTAssertFalse(OtpAuth.isUsable("hello world"))
    }

    /// Accepted keys produce codes in the Rust core (RFC 6238 test vector, SHA-1, 8 digits at t=59).
    func testAcceptedKeysWorkInTheCore() throws {
        let key = valid("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8").value
        let c = try totpCode(secret: key, unixSeconds: 59)
        XCTAssertEqual(c.code, "94287082")
        XCTAssertEqual(c.period, 30)
        XCTAssertEqual(try totpCode(secret: valid("jbsw y3dp ehpk 3pxp").value, unixSeconds: 0).code.count, 6)
    }
}
