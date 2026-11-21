import Foundation
@testable import PassAuthKit
import XCTest

/// The hand-off the PassAuth app leaves for "PassAuth for Safari" (Shared/SafariHandoff.swift):
/// server, email and Secret Key of the unlocked active account, nothing else.
final class SafariHandoffTests: XCTestCase {
    func testUnlockedAccountGivesServerEmailAndSecretKey() throws {
        let h = try XCTUnwrap(SafariHandoff.make(status: .unlocked, server: "https://vault.example.com", email: "alex@example.com", secretKey: "A3-ABCDEF"))
        XCTAssertEqual(h, SafariHandoff(server: "https://vault.example.com", email: "alex@example.com", secretKey: "A3-ABCDEF"))
    }

    func testLockedOrSignedOutGivesNothing() {
        XCTAssertNil(SafariHandoff.make(status: .locked, server: "https://vault.example.com", email: "a@b.c", secretKey: nil))
        XCTAssertNil(SafariHandoff.make(status: .setup, server: "", email: "", secretKey: nil))
        XCTAssertNil(SafariHandoff.make(status: .unlocked, server: "", email: "a@b.c", secretKey: nil))
    }

    func testJsonHasOnlyServerEmailAndSecretKey() throws {
        let data = try SafariHandoff(server: "https://s", email: "e@x", secretKey: nil).json()
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(obj.keys), ["server", "email"])
        let withKey = try SafariHandoff(server: "https://s", email: "e@x", secretKey: "K").json()
        let obj2 = try XCTUnwrap(JSONSerialization.jsonObject(with: withKey) as? [String: Any])
        XCTAssertEqual(Set(obj2.keys), ["server", "email", "secretKey"])
    }
}
