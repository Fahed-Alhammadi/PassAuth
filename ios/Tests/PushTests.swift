import Foundation
import PassAuthKit
import XCTest
@testable import PassAuth

/// Sign-in request notifications: token encoding, the registration requests, gating on the
/// server's `push` feature, the vault card rule and the notification payload.
@MainActor
final class PushTests: XCTestCase {
    func testTokenHexIsLowerCaseTwoDigitsPerByte() {
        XCTAssertEqual(PushRules.hex(Data([0x00, 0x01, 0x0f, 0x10, 0xab, 0xff])), "00010f10abff")
        XCTAssertEqual(PushRules.hex(Data()), "")
        let token = Data((0..<32).map { UInt8($0 * 7 & 0xff) })
        let hex = PushRules.hex(token)
        XCTAssertEqual(hex.count, 64)
        XCTAssertEqual(hex, token.map { String(format: "%02x", $0) }.joined())
        XCTAssertTrue(PushRules.validToken(hex))
    }

    func testTokenValidationMatchesTheServer() {
        XCTAssertTrue(PushRules.validToken(String(repeating: "a", count: 64)))
        XCTAssertTrue(PushRules.validToken(String(repeating: "0", count: 200)))
        XCTAssertFalse(PushRules.validToken(String(repeating: "a", count: 63)))
        XCTAssertFalse(PushRules.validToken(String(repeating: "a", count: 201)))
        XCTAssertFalse(PushRules.validToken(String(repeating: "A", count: 64)))
        XCTAssertFalse(PushRules.validToken(String(repeating: "g", count: 64)))
    }

    func testEnvironmentAndBody() {
        XCTAssertEqual(PushRules.environment(debug: true), "sandbox")
        XCTAssertEqual(PushRules.environment(debug: false), "production")
        // The tests run a debug build.
        XCTAssertEqual(PushRules.environment, "sandbox")
        let t = String(repeating: "ab", count: 32)
        let body = PushRules.registerBody(token: t, environment: "production")
        XCTAssertEqual(body, ["platform": "apns", "token": .string(t), "environment": "production"])
        XCTAssertEqual(body.text, #"{"environment":"production","platform":"apns","token":"\#(t)"}"#)
        XCTAssertEqual(PushRules.path, "/account/push")
    }

    func testFeatureGate() {
        XCTAssertTrue(PushRules.offered(features: ["login_with_device", "push"]))
        XCTAssertFalse(PushRules.offered(features: ["login_with_device"]))
        XCTAssertFalse(PushRules.offered(features: []))
        XCTAssertFalse(PushRules.offered(features: nil))
    }

    func testPermissionAndOffer() {
        XCTAssertEqual(PushRules.permission(0), .notAsked)
        XCTAssertEqual(PushRules.permission(1), .denied)
        XCTAssertEqual(PushRules.permission(2), .allowed)
        XCTAssertEqual(PushRules.permission(3), .allowed)
        XCTAssertEqual(PushRules.permission(4), .allowed)
        XCTAssertEqual(PushRules.permission(9), .unknown)
        XCTAssertTrue(PushRules.showOffer(permission: .notAsked, dismissed: false, offered: true))
        XCTAssertFalse(PushRules.showOffer(permission: .notAsked, dismissed: true, offered: true))
        XCTAssertFalse(PushRules.showOffer(permission: .notAsked, dismissed: false, offered: false))
        XCTAssertFalse(PushRules.showOffer(permission: .allowed, dismissed: false, offered: true))
        XCTAssertFalse(PushRules.showOffer(permission: .denied, dismissed: false, offered: true))
        XCTAssertFalse(PushRules.showOffer(permission: .unknown, dismissed: false, offered: true))
    }

    func testPayload() {
        XCTAssertTrue(PushRules.isSignInRequest(["aps": ["alert": "x"], "passauth": ["kind": "auth_request"]]))
        XCTAssertFalse(PushRules.isSignInRequest(["passauth": ["kind": "other"]]))
        XCTAssertFalse(PushRules.isSignInRequest(["aps": ["alert": "x"]]))
        XCTAssertFalse(PushRules.isSignInRequest(["passauth": "auth_request"]))
    }

    // MARK: Registration

    private struct Sent: Equatable {
        let account: String
        let method: String
        let body: JSON?
    }

    private final class Fake {
        var sent: [Sent] = []
        var features: [String: [String]?] = [:]
        var failing: Set<String> = []
    }

    private func registrar(_ fake: Fake, environment: String = "sandbox") -> PushRegistrar {
        PushRegistrar(environment: environment, send: { id, method, body in
            fake.sent.append(Sent(account: id, method: method, body: body))
            if fake.failing.contains(id) { throw UserError("offline") }
        }, features: { id in fake.features[id] ?? nil })
    }

    private let token1 = String(repeating: "1a", count: 32)
    private let token2 = String(repeating: "2b", count: 32)

    func testRegistersOnlyWithServersOfferingPushOncePerToken() async {
        let fake = Fake()
        fake.features = ["a": ["push"], "b": ["login_with_device"], "c": nil]
        let r = registrar(fake)
        await r.sync(token: token1, signedIn: ["a", "b", "c"])
        XCTAssertEqual(fake.sent, [Sent(account: "a", method: "PUT", body: PushRules.registerBody(token: token1, environment: "sandbox"))])
        XCTAssertEqual(r.registered, ["a": token1])
        // Again with the same token (app back on screen): nothing new.
        await r.sync(token: token1, signedIn: ["a", "b", "c"])
        XCTAssertEqual(fake.sent.count, 1)
        // The admin turned push on for b's server.
        fake.features["b"] = ["push"]
        await r.sync(token: token1, signedIn: ["a", "b", "c"])
        XCTAssertEqual(fake.sent.map(\.account), ["a", "b"])
    }

    func testNewTokenRegistersAgain() async {
        let fake = Fake()
        fake.features = ["a": ["push"]]
        let r = registrar(fake, environment: "production")
        await r.sync(token: token1, signedIn: ["a"])
        await r.sync(token: token2, signedIn: ["a"])
        XCTAssertEqual(fake.sent.map(\.body), [
            PushRules.registerBody(token: token1, environment: "production"),
            PushRules.registerBody(token: token2, environment: "production"),
        ])
        XCTAssertEqual(r.registered, ["a": token2])
    }

    func testNoTokenOrInvalidTokenSendsNothing() async {
        let fake = Fake()
        fake.features = ["a": ["push"]]
        let r = registrar(fake)
        await r.sync(token: nil, signedIn: ["a"])
        await r.sync(token: "abc", signedIn: ["a"])
        XCTAssertTrue(fake.sent.isEmpty)
    }

    func testFailureIsRetriedAndSignedOutAccountsAreForgotten() async {
        let fake = Fake()
        fake.features = ["a": ["push"]]
        fake.failing = ["a"]
        let r = registrar(fake)
        await r.sync(token: token1, signedIn: ["a"])
        XCTAssertEqual(r.registered, [:])
        fake.failing = []
        await r.sync(token: token1, signedIn: ["a"])
        XCTAssertEqual(r.registered, ["a": token1])
        // Signed out elsewhere (session ended): forgotten, so the next sign-in registers again.
        await r.sync(token: token1, signedIn: [])
        XCTAssertEqual(r.registered, [:])
        await r.sync(token: token1, signedIn: ["a"])
        XCTAssertEqual(fake.sent.filter { $0.method == "PUT" }.count, 3)
    }

    func testUnregisterSendsDeleteAndForgets() async {
        let fake = Fake()
        fake.features = ["a": ["push"]]
        let r = registrar(fake)
        await r.sync(token: token1, signedIn: ["a"])
        await r.unregister("a")
        XCTAssertEqual(fake.sent.last, Sent(account: "a", method: "DELETE", body: nil))
        XCTAssertEqual(r.registered, [:])
        // Failing DELETE (offline) is fine: best effort.
        fake.failing = ["a"]
        await r.unregister("a")
        XCTAssertEqual(fake.sent.last?.method, "DELETE")
    }

    func testUnregisterDoesNotWaitForASlowServer() async {
        let r = PushRegistrar(environment: "sandbox", send: { _, _, _ in
            try await Task.sleep(for: .seconds(30))
        }, features: { _ in ["push"] })
        let start = Date()
        await r.unregister("a", timeout: .milliseconds(200))
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }
}
