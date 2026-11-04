import PassAuthCore
import XCTest

/// Settings → Account security against the throwaway server (debug builds): change the master
/// password (turning the Secret Key on), lock and unlock with the new password, set up the
/// authenticator app (codes from the core's `totpCode`), recovery codes guard, sign out, sign
/// in with two-step login, turn the authenticator app off.
@MainActor
final class AccountSecurityUITests: UITestBase {
    private let newPassword = "Copper-Lantern-Meadow-97!"

    private func scrollTo(_ e: XCUIElement, max: Int = 8) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    /// iOS offers to save typed passwords in its own Passwords app ("Save Password?"): not now.
    private func dismissSavePassword(wait seconds: TimeInterval = 3) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            for root in [app, springboard] {
                let b = root.descendants(matching: .button).matching(NSPredicate(format: "label == 'Not Now'")).firstMatch
                if b.exists && b.isHittable {
                    shot("system-save-password")
                    b.tap()
                    sleep(1)
                    return
                }
            }
            usleep(300_000)
        } while Date() < deadline
    }

    private func securityPage() {
        dismissSavePassword()
        tab("Settings")
        if !app.buttons["settings.security"].waitForExistence(timeout: 3) {
            dismissSavePassword()
            tab("Settings")
            var n = 0
            while !app.buttons["settings.security"].exists && !app.navigationBars["Settings"].exists && n < 4 {
                back()
                n += 1
            }
        }
        wait(app.buttons["settings.security"]).tap()
    }

    /// Wait for a fresh 30 s period (the server accepts each period's code once).
    private func freshCode(_ secret: String, after used: String? = nil) throws -> String {
        var c = try totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        while c.remaining < 8 || c.code == used {
            sleep(UInt32(c.remaining) + 1)
            c = try totpCode(secret: secret, unixSeconds: UInt64(Date().timeIntervalSince1970))
        }
        return c.code
    }

    func testChangePasswordAndTwoStep() async throws {
        continueAfterFailure = false
        let stamp = Int(Date().timeIntervalSince1970)
        let email = "sec-\(stamp)@example.com"
        let srv = TestServer(server)
        try await srv.register(email: email, password: password, name: "Grace Hopper")

        app.launchArguments = ["-PAResetState", "-PASkipPermissions"]
        app.launch()
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        wait(app.navigationBars["Vault"], 60)
        dismissSavePassword(wait: 8)

        // The security page links to the native screens (no web vault shortcuts any more).
        securityPage()
        let change = app.buttons["settings.changePassword"]
        scrollTo(change)
        shot("sec-01-security-page")
        change.tap()
        wait(app.navigationBars["Change master password"])

        // Checks before anything is sent: wrong confirmation.
        type(app.secureTextFields["pw.current"], password)
        type(app.secureTextFields["pw.confirm"], newPassword + "x")
        type(app.secureTextFields["pw.new"], newPassword)
        dismissKeyboard()
        toggleOn("pw.useSecretKey")
        let submit = app.buttons["pw.submit"]
        scrollTo(submit)
        submit.tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS \"don't match\"")).firstMatch)
        shot("sec-02-change-password-mismatch")
        replace(app.secureTextFields["pw.confirm"], newPassword)
        dismissKeyboard()
        scrollTo(submit)
        submit.tap()
        // Confirmation: says the other devices get signed out.
        let alert = app.alerts.firstMatch
        wait(alert)
        XCTAssertTrue(alert.staticTexts.containing(NSPredicate(format: "label CONTAINS 'other devices will be signed out'")).firstMatch.exists)
        shot("sec-03-change-password-confirm")
        alert.buttons["Change master password"].tap()
        dismissSavePassword(wait: 8)

        // The new Secret Key, once; Done only after "I saved it", no swipe-away before.
        wait(app.staticTexts["newSecretKey"], 90)
        XCTAssertFalse(app.buttons["newKey.done"].isEnabled)
        shot("sec-04-new-secret-key")
        app.swipeDown(velocity: .fast)
        XCTAssertTrue(app.staticTexts["newSecretKey"].waitForExistence(timeout: 3), "can't be swiped away before confirming")
        toggleOn("savedToggle")
        app.buttons["newKey.done"].tap()
        // Back on Account security (the "Master password changed" notice may already be gone
        // behind iOS's own save-password prompt).
        shot("sec-05-changed")
        dismissSavePassword()
        wait(app.buttons["settings.changePassword"], 20)

        // Lock, then the old password fails and the new one unlocks (Secret Key kept on the device).
        securityPage()
        wait(app.buttons["lockNow"]).tap()
        let field = wait(app.secureTextFields["Master password"], 30)
        type(field, password)
        button("Unlock").tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'Wrong master password'")).firstMatch, 60)
        shot("sec-06-old-password-rejected")
        replace(app.secureTextFields["Master password"], newPassword)
        button("Unlock").tap()
        wait(app.navigationBars["Vault"], 60)

        // Two-step login: authenticator app.
        securityPage()
        let twoStep = app.buttons["settings.twoStep"]
        scrollTo(twoStep)
        twoStep.tap()
        wait(app.navigationBars["Two-step login"])
        wait(app.buttons["totp.setup"], 30)
        shot("sec-07-two-step-off")
        app.buttons["totp.setup"].tap()
        let secretText = wait(app.staticTexts["totp.secret"], 30)
        wait(app.images["totp.qr"])
        shot("sec-08-totp-setup")
        let secret = secretText.label.replacingOccurrences(of: "Setup key: ", with: "").replacingOccurrences(of: " ", with: "")
        XCTAssertGreaterThanOrEqual(secret.count, 16)
        // "Open in authenticator app": iOS hands the otpauth:// link to an app that takes it
        // (on the simulator, Apple's Passwords app), then back to PassAuth, setup still open.
        app.buttons["totp.open"].tap()
        let passwords = XCUIApplication(bundleIdentifier: "com.apple.Passwords")
        if passwords.wait(for: .runningForeground, timeout: 10) {
            sleep(2)
            shot("sec-08b-opened-in-authenticator")
            app.activate()
        } else {
            notice(contains: "No app on this device opens authenticator setup links")
        }
        wait(app.staticTexts["totp.secret"], 20)
        // A wrong code first.
        let codeField = app.textFields["totp.code"]
        scrollTo(codeField)
        type(codeField, "000000")
        let enable = app.buttons["totp.enable"]
        scrollTo(enable)
        enable.tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS \"That code isn't right\"")).firstMatch, 30)
        shot("sec-09-totp-wrong-code")
        let code = try freshCode(secret)
        replace(codeField, code)
        scrollTo(enable)
        enable.tap()

        // Recovery codes: Done only after "I saved them", no swipe-away before.
        wait(app.switches["codes.saved"], 30)
        XCTAssertFalse(app.buttons["codes.done"].isEnabled)
        shot("sec-10-recovery-codes")
        app.swipeDown(velocity: .fast)
        XCTAssertTrue(app.switches["codes.saved"].waitForExistence(timeout: 3), "can't be swiped away before confirming")
        toggleOn("codes.saved")
        app.buttons["codes.done"].tap()
        wait(app.buttons["totp.off"], 30)
        shot("sec-11-two-step-on")

        dismissSavePassword(wait: 1)
        // Sign out, then sign in with the new password and an authenticator code.
        tab("Settings")
        while !app.buttons["settings.account"].exists { back() }
        wait(app.buttons["settings.account"]).tap()
        let logout = app.buttons["logout"]
        scrollTo(logout)
        logout.tap()
        confirm("Log out")
        wait(app.staticTexts["Sign in to PassAuth"], 30)
        // The sign-in screen remembers the last account's email.
        let emailField = wait(app.textFields["Email"])
        if (emailField.value as? String) != email { replace(emailField, email) }
        type(app.secureTextFields["Master password"], newPassword)
        dismissKeyboard()
        button("Sign in").tap()
        wait(app.staticTexts["Two-step login"], 60)
        dismissSavePassword(wait: 4)
        let next = try freshCode(secret, after: code)
        let codeInput = wait(app.textFields["6-digit code"])
        for _ in 0..<3 where !codeInput.hasFocus {
            codeInput.tap()
            sleep(1)
            dismissSavePassword(wait: 1)
        }
        codeInput.typeText(next)
        shot("sec-12-sign-in-two-step")
        dismissKeyboard()
        button("Verify and sign in").tap()
        wait(app.navigationBars["Vault"], 60)

        dismissSavePassword()
        // Turn the authenticator app off: master password first (destructive action).
        securityPage()
        scrollTo(app.buttons["settings.twoStep"])
        app.buttons["settings.twoStep"].tap()
        wait(app.buttons["totp.off"], 30).tap()
        wait(app.secureTextFields["reauth.password"])
        shot("sec-13-turn-off-reauth")
        type(app.secureTextFields["reauth.password"], newPassword)
        dismissKeyboard()
        app.buttons["reauth.confirm"].tap()
        notice(contains: "Authenticator app turned off")
        wait(app.buttons["totp.setup"], 30)
        shot("sec-14-two-step-off-again")
    }
}
