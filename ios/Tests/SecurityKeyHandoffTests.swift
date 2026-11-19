import Foundation
import PassAuthKit
import XCTest

/// Two-step login with a security key through the server's key page: the page that is opened
/// (only the server's own https address for the relying party) and the answers taken back (only
/// `passauth://two-step-key`, version 1, for this sign-in's challenge).
final class SecurityKeyHandoffTests: XCTestCase {
    private let challenge = "AAECAwQFBgcICQoLDA0ODw"
    /// The state this test's hand-off opened with (16 bytes, base64url).
    private let state = "c3RhdGUtc3RhdGUtc3RhdA"
    private let server = "https://vault.example.com"

    private func plan(_ start: JSON, server: String? = nil) throws -> SecurityKeyHandoff.Plan {
        try SecurityKeyHandoff.plan(start: start, server: server ?? self.server, state: state)
    }

    private func start(page: String? = "https://vault.example.com/two-step/key", rpId: String? = "vault.example.com", challenge: String? = nil) -> JSON {
        var pk: [String: JSON] = ["challenge": .string(challenge ?? self.challenge), "userVerification": "preferred",
                                  "allowCredentials": [["type": "public-key", "id": "a2V5"]], "timeout": 60000]
        if let rpId { pk["rpId"] = .string(rpId) }
        var o: [String: JSON] = ["options": ["publicKey": .object(pk)]]
        if let page { o["key_page"] = .string(page) }
        return .object(o)
    }

    private func fragment(_ url: URL) -> [String: String] {
        var out: [String: String] = [:]
        for pair in (URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedFragment ?? "").split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            out[String(kv[0])] = kv.count > 1 ? String(kv[1]) : ""
        }
        return out
    }

    private func credential(challenge: String? = nil, type: String = "webauthn.get") -> JSON {
        let client = #"{"type":"\#(type)","challenge":"\#(challenge ?? self.challenge)","origin":"https://vault.example.com","crossOrigin":false}"#
        return ["id": "a2V5", "rawId": "a2V5", "type": "public-key", "clientExtensionResults": [:],
                "response": ["clientDataJSON": .string(SecurityKeyHandoff.base64urlEncode(Data(client.utf8))),
                             "authenticatorData": "YXV0aA", "signature": "c2ln", "userHandle": nil]]
    }

    /// The page's answer; `state` is added at the end (nil: left out).
    private func callback(_ fragment: String, scheme: String = "passauth", host: String = "two-step-key", state: String?? = .some(nil)) -> URL {
        let st: String? = switch state { case .some(let v): v ?? self.state; case .none: nil }
        return URL(string: "\(scheme)://\(host)#\(fragment)" + (st.map { "&state=\($0)" } ?? ""))!
    }

    func testPlanOpensTheKeyPageWithTheOptions() throws {
        let plan = try plan(start())
        XCTAssertEqual(plan.url.scheme, "https")
        XCTAssertEqual(plan.url.host, "vault.example.com")
        XCTAssertEqual(plan.url.path, "/two-step/key")
        XCTAssertNil(plan.url.query)
        XCTAssertEqual(plan.challenge, Data(0..<16))
        let f = fragment(plan.url)
        XCTAssertEqual(f["v"], "1")
        XCTAssertEqual(f["return"], "app")
        XCTAssertEqual(f["state"], state)
        XCTAssertEqual(plan.state, state)
        XCTAssertEqual(Set(f.keys), ["v", "options", "return", "state"])
        // The options exactly as the start answer had them (`{publicKey: …}`).
        let options = try JSON.parse(XCTUnwrap(SecurityKeyHandoff.base64urlDecode(XCTUnwrap(f["options"]))))
        XCTAssertEqual(options, start()["options"])
        XCTAssertFalse(f["options"]!.contains("="), "no padding")
        // Bare publicKey options are read too (the page reads both).
        let bare: JSON = ["options": start()["options"]!["publicKey"]!, "key_page": "https://vault.example.com/two-step/key"]
        XCTAssertEqual(try self.plan(bare).challenge, Data(0..<16))
    }

    func testPlanRefusesAnotherAddress() {
        let bad: [JSON] = [
            start(page: "http://vault.example.com/two-step/key"),
            start(page: "https://evil.example.net/two-step/key"),
            start(page: "https://sub.vault.example.com/two-step/key"),
            start(page: "https://vault.example.com.evil.net/two-step/key"),
            start(page: "https://user@vault.example.com/two-step/key"),
            start(page: "https://vault.example.com/two-step/key#x=1"),
            start(page: "javascript:alert(1)"),
            start(page: nil),
            start(rpId: nil),
            start(rpId: ""),
        ]
        for s in bad {
            XCTAssertThrowsError(try plan(s), s.text) { e in
                XCTAssertEqual((e as? UserError)?.message, SecurityKeyHandoff.mismatch)
            }
        }
        // Case and a port don't matter for the host check.
        XCTAssertNoThrow(try plan(start(page: "https://Vault.Example.com:8443/two-step/key")))
        XCTAssertNoThrow(try plan(start(), server: "https://VAULT.example.com:8443/base"))
        // The key page must be on the server this app signs in to, even when rpId agrees with it.
        for other in ["https://other.example.com", "https://example.com", "", "not a url"] {
            XCTAssertThrowsError(try plan(start(), server: other), other) { e in
                XCTAssertEqual((e as? UserError)?.message, SecurityKeyHandoff.mismatch)
            }
        }
        XCTAssertThrowsError(try plan(start(page: "https://evil.example.net/two-step/key", rpId: "evil.example.net")))
        // Without a usable state nothing opens.
        XCTAssertThrowsError(try SecurityKeyHandoff.plan(start: start(), server: server, state: ""))
        XCTAssertThrowsError(try SecurityKeyHandoff.plan(start: start(), server: server, state: "short"))
        // No usable challenge: not a security key answer at all.
        XCTAssertThrowsError(try plan(start(challenge: "")))
        XCTAssertThrowsError(try plan(start(challenge: "not base64!")))
        XCTAssertThrowsError(try plan(["key_page": "https://vault.example.com/two-step/key"]))
    }

    func testAnswerWithTheCredentialForThisChallenge() throws {
        let plan = try plan(start())
        let c = credential()
        let url = callback("v=1&credential=\(SecurityKeyHandoff.base64urlEncode(c.data))")
        XCTAssertEqual(SecurityKeyHandoff.answer(url, for: plan), .credential(c))
        // Padded base64url is read too.
        let padded = SecurityKeyHandoff.base64urlEncode(c.data) + String(repeating: "=", count: (4 - SecurityKeyHandoff.base64urlEncode(c.data).count % 4) % 4)
        XCTAssertEqual(SecurityKeyHandoff.answer(callback("v=1&credential=\(padded)"), for: plan), .credential(c))
    }

    func testCancelled() throws {
        let plan = try plan(start())
        XCTAssertEqual(SecurityKeyHandoff.answer(callback("v=1&error=cancelled"), for: plan), .cancelled)
        XCTAssertNil(SecurityKeyHandoff.answer(callback("v=1&error=other"), for: plan))
        XCTAssertNil(SecurityKeyHandoff.answer(callback("v=1&error=cancelledx"), for: plan))
        XCTAssertNil(SecurityKeyHandoff.answer(callback("v=1&error="), for: plan))
        // A cancel needs this hand-off's state too.
        XCTAssertNil(SecurityKeyHandoff.answer(callback("v=1&error=cancelled", state: .none), for: plan))
        XCTAssertNil(SecurityKeyHandoff.answer(callback("v=1&error=cancelled", state: "b3RoZXItb3RoZXItb3RoZQ"), for: plan))
    }

    func testAnswersThatAreIgnored() throws {
        let plan = try plan(start())
        let good = SecurityKeyHandoff.base64urlEncode(credential().data)
        let other = SecurityKeyHandoff.base64urlEncode(credential(challenge: "AQEBAQEBAQEBAQEBAQEBAQ").data)
        let create = SecurityKeyHandoff.base64urlEncode(credential(type: "webauthn.create").data)
        let ignored: [URL] = [
            callback("v=1&credential=\(other)"),            // another sign-in's challenge
            callback("v=1&credential=\(create)"),           // not an assertion
            callback("v=2&credential=\(good)"),             // another version
            callback("credential=\(good)"),                 // no version
            callback("v=1&credential=\(good)", scheme: "https", host: "vault.example.com"),
            callback("v=1&credential=\(good)", host: "other"),
            callback("v=1&v=1&credential=\(good)"),         // repeated keys
            callback("v=1&credential=\(good)&error=cancelled"),
            callback("v=1&credential=!!!!"),
            callback("v=1&credential=\(SecurityKeyHandoff.base64urlEncode(Data("[1]".utf8)))"),
            callback("v=1"),
            URL(string: "passauth://two-step-key?v=1&credential=\(good)&state=\(state)")!, // query, not fragment
            callback("v=1&credential=\(good)", state: .none),                          // no state
            callback("v=1&credential=\(good)", state: "b3RoZXItb3RoZXItb3RoZQ"),        // another hand-off's state
            callback("v=1&credential=\(good)&state=\(state)"),                         // repeated state
        ]
        for url in ignored { XCTAssertNil(SecurityKeyHandoff.answer(url, for: plan), url.absoluteString) }
    }

    func testNewStateIsRandom() {
        let a = SecurityKeyHandoff.newState(), b = SecurityKeyHandoff.newState()
        XCTAssertEqual(a.count, 22)
        XCTAssertEqual(SecurityKeyHandoff.base64urlDecode(a)?.count, 16)
        XCTAssertNotEqual(a, b)
    }

    func testBase64url() {
        let d = Data([0xfb, 0xff, 0xfe, 0x00, 0x01])
        XCTAssertEqual(SecurityKeyHandoff.base64urlEncode(d), "-__-AAE")
        XCTAssertEqual(SecurityKeyHandoff.base64urlDecode("-__-AAE"), d)
        XCTAssertEqual(SecurityKeyHandoff.base64urlDecode("-__-AAE="), d)
        XCTAssertNil(SecurityKeyHandoff.base64urlDecode("+//+AAE"))
        XCTAssertNil(SecurityKeyHandoff.base64urlDecode(""))
        XCTAssertNil(SecurityKeyHandoff.base64urlDecode("A"))
    }
}
