import XCTest

/// Sign-in request notifications against a throwaway server with the `push` feature (debug
/// builds; server 0.17+ with push on): no card or prompt in the vault (App Review 5.1.1(iv): the
/// prompt comes only from the user's own switch), and Settings → Account security's switch, which
/// asks iOS when turned on. Run on a simulator where PassAuth was just installed (notifications
/// not asked yet). Screenshots get
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

    func testSettingsSwitch() async throws {
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
        // No notifications card or prompt in the vault, although the server offers push.
        _ = tapSystem("Not Now", wait: 10)
        XCTAssertFalse(app.descendants(matching: .any)["notice.push"].firstMatch.exists)
        XCTAssertFalse(tapSystem("Allow", wait: 3), "a notification prompt appeared without the user turning the switch on")

        // Account security: the switch is off, not asked yet.
        securityPage()
        let toggle = app.switches["pushToggle"].firstMatch
        scrollTo(toggle)
        wait(toggle)
        XCTAssertEqual(toggle.value as? String, "0")
        shot("push-settings-off\(suffix)")

        // Turn on with the switch: iOS asks, Allow, the switch stays on.
        toggle.tap()
        XCTAssertTrue(tapSystem("Allow", wait: 10), "no notification prompt")
        let deadline = Date().addingTimeInterval(10)
        while (toggle.value as? String) != "1" && Date() < deadline { usleep(300_000) }
        XCTAssertEqual(toggle.value as? String, "1")
        shot("push-settings-on\(suffix)")
    }
}
