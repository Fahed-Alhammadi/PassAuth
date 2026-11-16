import PassAuthCore
import XCTest

/// Sign in with another device, the approving side, against the throwaway server (debug
/// builds): the test acts as the new device (`LoginRequestKey` from the core, the server's
/// request API), the app answers. The sheet offers three sets of words; the right one approves
/// and shows the code the new device needs (checked with the core), the wrong one denies, and
/// "Not now" leaves the request open. What the device claims to be is shown cleaned.
@MainActor
final class DeviceLoginUITests: UITestBase {
    private struct Request {
        let key: LoginRequestKey
        let id: String
        let accessCode: String
    }

    /// The new device asks to sign in to `email`, calling itself `name`.
    private func requestSignIn(_ srv: TestServer, email: String, name: String) async throws -> Request {
        let key = try LoginRequestKey.generate()
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let access = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let r = try await srv.call("POST", "/auth/requests", [
            "email": email, "public_key": key.publicKey(), "access_code": access,
            "device_id": UUID().uuidString.lowercased(), "device_name": name, "device_kind": "mobile",
        ])
        return Request(key: key, id: r["id"] as! String, accessCode: access)
    }

    private func status(_ srv: TestServer, _ r: Request) async throws -> [String: Any] {
        try await srv.call("GET", "/auth/requests/\(r.id)", headers: ["X-PassAuth-Access-Code": r.accessCode])
    }

    /// The new device's poll until the request was answered.
    private func answer(_ srv: TestServer, _ r: Request) async throws -> [String: Any] {
        for _ in 0..<30 {
            let s = try await status(srv, r)
            if s["status"] as? String != "pending" { return s }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw TestServer.Failure(description: "request \(r.id) still pending")
    }

    private func signIn(_ email: String) {
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        dismissSavePassword(wait: 12)
    }

    /// iOS's own "Save Password?" for the sign-in form (when the simulator's password manager is
    /// on) covers the app: answer "Not Now".
    private func dismissSavePassword(wait seconds: TimeInterval) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            for root in [app, springboard] {
                let b = root.descendants(matching: .button).matching(NSPredicate(format: "label == 'Not Now'")).firstMatch
                if b.exists && b.isHittable {
                    b.tap()
                    sleep(1)
                    return
                }
            }
            usleep(300_000)
        } while Date() < deadline
    }

    /// The sheet for a new request: live sync lists it; if the socket is slow, coming back to
    /// the app lists it too.
    private func sheet() -> XCUIElement {
        let first = app.buttons["authRequest.choice0"]
        if first.waitForExistence(timeout: 20) { return first }
        XCUIDevice.shared.press(.home)
        sleep(1)
        app.activate()
        return wait(first, 30)
    }

    /// Tap `element` until `result` shows: iOS's own "Save Password?" for the sign-in form can
    /// come up late over the app and take a tap to go away (it isn't always reachable to dismiss).
    private func tap(_ element: XCUIElement, until result: XCUIElement, timeout: TimeInterval = 30) {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            if element.exists && element.isHittable && element.isEnabled { element.tap() }
            if result.waitForExistence(timeout: 4) { return }
            dismissSavePassword(wait: 1)
        } while Date() < deadline
        wait(result, 1)
    }

    /// The choice button showing `phrase` (or the first one that doesn't, for a decoy), once it takes taps.
    private func choice(_ phrase: String, matching: Bool) throws -> XCUIElement {
        let buttons = (0..<3).map { app.buttons["authRequest.choice\($0)"] }
        let b = try XCTUnwrap(buttons.first { ($0.label == phrase) == matching }, "choices: \(buttons.map(\.label))")
        // The choices take taps a second after the sheet's content appeared.
        let deadline = Date().addingTimeInterval(5)
        while !b.isEnabled && Date() < deadline { usleep(200_000) }
        XCTAssertTrue(b.isEnabled)
        return b
    }

    func testApproveWithTheWordsTheNewDeviceShows() async throws {
        continueAfterFailure = false
        let email = "dl-\(Int(Date().timeIntervalSince1970))@example.com"
        let srv = TestServer(server)
        try await srv.register(email: email, password: password, name: "Ada Lovelace")
        // Waiting before the app signs in, from a device claiming a misleading name (the server
        // cleans it too; the app's own cleaning is unit-tested against a server that doesn't).
        let spoof = "Your iPhone\u{202E}kcehc ytiruces\u{202C}\n\n" + String(repeating: "!", count: 80)
        let first = try await requestSignIn(srv, email: email, name: spoof)

        app.launchArguments = ["-PAResetState", "-PASkipPermissions"]
        app.launch()
        signIn(email)

        wait(app.buttons["authRequest.choice0"], 60)
        XCTAssertTrue(app.buttons["authRequest.notNow"].exists)
        XCTAssertTrue(app.buttons["authRequest.none"].exists)
        let device = app.descendants(matching: .any).matching(identifier: "authRequest.device").firstMatch
        let shownName = try XCTUnwrap(device.value as? String)
        XCTAssertFalse(shownName.unicodeScalars.contains { $0.properties.generalCategory == .format || $0.properties.generalCategory == .control })
        XCTAssertTrue(shownName.hasPrefix("Your iPhone"))
        XCTAssertLessThanOrEqual(shownName.unicodeScalars.count, 65, "at most 64 characters and the cut mark")
        shot("dl-01-which-words")

        // The right words: the code the new device needs, until Done.
        tap(try choice(first.key.phrase(), matching: true), until: app.staticTexts["authRequest.code"])
        let codeText = wait(app.staticTexts["authRequest.code"], 30)
        let code = codeText.label.filter { $0.isASCII && $0.isNumber }
        XCTAssertEqual(code.count, 6)
        shot("dl-02-code")
        let approved = try await answer(srv, first)
        XCTAssertEqual(approved["status"] as? String, "approved")
        let opened = try first.key.open(sealed: approved["sealed_key"] as! String, accountId: approved["user_id"] as! String, requestId: first.id)
        XCTAssertThrowsError(try opened.secretKey(), "nothing before the code")
        try opened.confirm(code: code)
        let bundle = String(decoding: try JSONSerialization.data(withJSONObject: approved["bundle"]!), as: UTF8.self)
        XCTAssertNoThrow(try opened.unlock(bundleJson: bundle), "the code shown confirms this approval")
        XCTAssertTrue(app.staticTexts["authRequest.code"].exists, "still shown after the new device used it")
        app.buttons["authRequest.done"].tap()
        XCTAssertTrue(app.staticTexts["authRequest.code"].waitForNonExistence(timeout: 5))

        // Words that aren't the new device's: denied, and the sheet says so.
        let second = try await requestSignIn(srv, email: email, name: "Pixel 9")
        _ = sheet()
        tap(try choice(second.key.phrase(), matching: false), until: app.staticTexts["authRequest.closed"])
        let closed = wait(app.staticTexts["authRequest.closed"], 30)
        XCTAssertEqual(closed.label, "Those aren't the words for this request, so it was denied.")
        shot("dl-03-wrong-words")
        app.buttons["authRequest.close"].tap()
        let denied = try await answer(srv, second)
        XCTAssertEqual(denied["status"] as? String, "denied")

        // Not now: no answer, the request stays open on the server.
        let third = try await requestSignIn(srv, email: email, name: "MacBook")
        _ = sheet()
        app.buttons["authRequest.notNow"].tap()
        XCTAssertTrue(app.buttons["authRequest.choice0"].waitForNonExistence(timeout: 5))
        let open = try await status(srv, third)
        XCTAssertEqual(open["status"] as? String, "pending")
    }
}
