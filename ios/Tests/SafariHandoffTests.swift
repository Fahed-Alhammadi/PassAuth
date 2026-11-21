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

    func testClearsWhenSignedOutOrTheItemIsAnotherAccounts() {
        let item = SafariHandoff(server: "https://vault.example.com", email: "alex@example.com", secretKey: "K")
        // Signed out: always cleared.
        XCTAssertTrue(SafariHandoff.shouldClear(status: .setup, server: "", email: "", stored: item))
        XCTAssertTrue(SafariHandoff.shouldClear(status: .loggedOut, server: item.server, email: item.email, stored: item))
        // One of several accounts logged out: the next active one is locked and isn't the item's.
        XCTAssertTrue(SafariHandoff.shouldClear(status: .locked, server: item.server, email: "sam@example.com", stored: item))
        XCTAssertTrue(SafariHandoff.shouldClear(status: .locked, server: "https://other.example.com", email: item.email, stored: item))
        // The same account, locked: kept, so Safari still offers it.
        XCTAssertFalse(SafariHandoff.shouldClear(status: .locked, server: item.server, email: "Alex@Example.com", stored: item))
        // Nothing stored: nothing to clear.
        XCTAssertFalse(SafariHandoff.shouldClear(status: .locked, server: item.server, email: "sam@example.com", stored: nil))
    }

    func testChangeKeyFollowsTheSecretKey() {
        let a = SafariHandoff.changeKey(activeId: "1", status: .unlocked, server: "s", email: "e", secretKey: "K1")
        let b = SafariHandoff.changeKey(activeId: "1", status: .unlocked, server: "s", email: "e", secretKey: "K2")
        XCTAssertNotEqual(a, b)
        XCTAssertFalse(a.contains("K1"))
    }
}
