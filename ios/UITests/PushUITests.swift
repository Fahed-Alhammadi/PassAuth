import XCTest

/// Sign-in request notifications against a throwaway server with the `push` feature (debug
/// builds; server 0.17+ with push on): the row on the first-launch screen, the one-time vault
/// card (Turn on → iOS prompt → card gone), and Settings → Account security's switch. Run on a
/// simulator where PassAuth was just installed (notifications not asked yet). Screenshots get
/// the `PA_SHOT_SUFFIX` (e.g. "-dark") so a run per appearance keeps both.
@MainActor
final class PushUITests: UITestBase {
    private var suffix: String { env["PA_SHOT_SUFFIX"] ?? "" }

    private func scrollTo(_ e: XCUIElement, max: Int = 8) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    /// iOS's own "Save Password?" and the notification prompt live in SpringBoard.
    private func tapSystem(_ label: String, wait seconds: TimeInterval) -> Bool {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            for root in [app, springboard] {
                let b = root.descendants(matching: .button).matching(NSPredicate(format: "label == %@", label)).firstMatch
                if b.exists && b.isHittable {
                    b.tap()
                    sleep(1)
                    return true
                }
            }
            usleep(300_000)
        } while Date() < deadline
        return false
    }

    private func securityPage() {
        _ = tapSystem("Not Now", wait: 1)
        tab("Settings")
        if !app.buttons["settings.security"].waitForExistence(timeout: 5) {
            _ = tapSystem("Not Now", wait: 3)
            tab("Settings")
        }
        wait(app.buttons["settings.security"]).tap()
    }

    func testOfferCardAndSettingsSwitch() async throws {
        continueAfterFailure = false
        let email = "push-\(Int(Date().timeIntervalSince1970))@example.com"
        try await TestServer(server).register(email: email, password: password, name: "Ada Lovelace")

        app.launchArguments = ["-PAResetState"]
        app.launch()

        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        wait(app.navigationBars["Vault"], 60)
        // The vault card (notifications not asked yet, the server offers push).
        wait(app.descendants(matching: .any)["notice.push"].firstMatch, 15)
        _ = tapSystem("Not Now", wait: 10)
        shot("push-vault-card\(suffix)")

        // Account security: the switch is off, not asked yet.
        securityPage()
        let toggle = app.switches["pushToggle"].firstMatch
        scrollTo(toggle)
        wait(toggle)
        XCTAssertEqual(toggle.value as? String, "0")
        shot("push-settings-off\(suffix)")

        // Turn on from the card: iOS asks, Allow, the card goes.
        tab("Vault")
        wait(app.buttons["notice.push.turnOn"]).tap()
        XCTAssertTrue(tapSystem("Allow", wait: 10), "no notification prompt")
        XCTAssertTrue(app.descendants(matching: .any)["notice.push"].firstMatch.waitForNonExistence(timeout: 10))

        securityPage()
        scrollTo(toggle)
        let deadline = Date().addingTimeInterval(10)
        while (toggle.value as? String) != "1" && Date() < deadline { usleep(300_000) }
        XCTAssertEqual(toggle.value as? String, "1")
        shot("push-settings-on\(suffix)")
    }
}
