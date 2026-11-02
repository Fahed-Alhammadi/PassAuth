import UIKit
import XCTest

/// The first-launch "Set up PassAuth" screen. Screenshots are named after the simulator's
/// appearance: run once in light and once in dark mode (`xcrun simctl ui <sim> appearance dark`).
/// Face ID is tried when it's enrolled and the host sends matches
/// (`xcrun simctl spawn <sim> notifyutil -p com.apple.BiometricKit_Sim.pearl.match`); then a
/// sign-in on the test server checks the one-time "Unlock with Face ID?" offer
/// (PA_PERM_SIGNIN=0 skips it).
@MainActor
final class PermissionsUITests: UITestBase {
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private var style: String { UITraitCollection.current.userInterfaceStyle == .dark ? "dark" : "light" }

    private func any(_ id: String) -> XCUIElement { app.descendants(matching: .any).matching(identifier: id).firstMatch }

    /// Answer a system alert (shown by SpringBoard or inside the app) with the first matching button.
    @discardableResult
    private func answerAlert(_ labels: [String], timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            for alert in [springboard.alerts.firstMatch, app.alerts.firstMatch] where alert.exists {
                for l in labels where alert.buttons[l].exists {
                    alert.buttons[l].tap()
                    return true
                }
            }
            usleep(250_000)
        }
        return false
    }

    func testPermissionsScreen() throws {
        continueAfterFailure = false
        app.launchArguments = ["-PAResetState"]
        app.launch()
        wait(app.staticTexts["Set up PassAuth"], 20)
        for title in ["AutoFill passwords & passkeys", "Camera", "Local network"] {
            wait(app.staticTexts[title].firstMatch)
        }
        XCTAssertTrue(app.buttons["perm.skip"].exists)
        shot("perm-01-intro-\(style)")

        // Camera: the system prompt, answered "Allow" (or allowed by an earlier run).
        let camera = app.buttons["perm.camera"]
        if camera.waitForExistence(timeout: 3) {
            camera.tap()
            answerAlert(["Allow", "OK"], timeout: 8)
        }
        wait(any("perm.camera.allowed"), 10)

        // Local network: the simulator doesn't ask; the browse comes back ready.
        let local = app.buttons["perm.localNetwork"]
        if local.exists {
            local.tap()
            answerAlert(["Allow"], timeout: 4)
        }
        wait(any("perm.localNetwork.allowed"), 20)

        // Face ID / Touch ID, when enrolled: the permission alert, then a match from the host.
        var biometrics = any("perm.biometrics.allowed").exists
        let bio = app.buttons["perm.biometrics"]
        if bio.exists {
            bio.tap()
            answerAlert(["OK", "Allow"], timeout: 5)
            biometrics = any("perm.biometrics.allowed").waitForExistence(timeout: 20)
        } else if !biometrics {
            wait(any("perm.biometrics.status"))
        }
        shot("perm-02-granted-\(style)")

        app.buttons["perm.continue"].tap()
        wait(app.textFields["Server address"], 10)

        // Shown once: a relaunch goes straight to the server address.
        app.terminate()
        app.launchArguments = []
        app.launch()
        wait(app.textFields["Server address"], 20)
        XCTAssertFalse(app.staticTexts["Set up PassAuth"].exists)

        // Biometrics allowed here: after the first sign-in the app offers biometric unlock once.
        guard biometrics, env["PA_PERM_SIGNIN"] != "0" else { return }
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        register(email: "perm\(Int(Date().timeIntervalSince1970))@example.com", name: "Grace Hopper", secretKey: false)
        let offer = app.alerts.firstMatch
        wait(offer, 10)
        XCTAssertTrue(offer.label.hasPrefix("Unlock with"), offer.label)
        shot("perm-03-offer-\(style)")
        offer.buttons["Turn on"].tap()
        notice(contains: "unlock is on")
        tab("Settings")
        app.buttons["settings.security"].tap()
        XCTAssertEqual(wait(app.switches["biometricToggle"]).value as? String, "1")
        // Only once.
        app.terminate()
        app.launchArguments = []
        app.launch()
        unlock()
        sleep(2)
        XCTAssertFalse(app.alerts.firstMatch.exists)
    }
}
