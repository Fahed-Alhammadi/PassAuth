import XCTest

/// End-to-end checks against a throwaway PassAuth server (debug builds only).
///
///   PA_SERVER   server address (default http://127.0.0.1:8091)
///   PA_SHOTS    folder for screenshots (optional)
///
/// Pass them to xcodebuild as TEST_RUNNER_PA_SERVER / TEST_RUNNER_PA_SHOTS.
/// `testFullFlow` creates fresh accounts; `testOfflineOpen` expects the server to be stopped
/// and the state left by `testFullFlow` (run it separately, afterwards).
@MainActor
class UITestBase: XCTestCase {
    let env = ProcessInfo.processInfo.environment
    var server: String { env["PA_SERVER"] ?? "http://127.0.0.1:8091" }
    let password = "Velvet-Orbit-Canyon-42!"
    let app = XCUIApplication()

    // MARK: Helpers

    func shot(_ name: String) {
        let png = XCUIScreen.main.screenshot().pngRepresentation
        let a = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        a.name = name
        a.lifetime = .keepAlways
        add(a)
        if let dir = env["PA_SHOTS"] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try? png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
        }
    }

    @discardableResult
    func wait(_ e: XCUIElement, _ timeout: TimeInterval = 20, file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        if !e.waitForExistence(timeout: timeout) { shot("fail-\(line)") }
        XCTAssertTrue(e.exists, "missing: \(e)", file: file, line: line)
        return e
    }

    func type(_ e: XCUIElement, _ text: String) {
        wait(e).tap()
        e.typeText(text)
    }

    func replace(_ e: XCUIElement, _ text: String) {
        wait(e).tap()
        if let v = e.value as? String, !v.isEmpty {
            e.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: v.count))
        }
        e.typeText(text)
    }

    func button(_ label: String) -> XCUIElement { app.buttons[label].firstMatch }

    /// Tap the last hittable button with this label (confirmation dialogs repeat the label of the button that opened them).
    func confirm(_ label: String) {
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            let all = app.buttons.matching(NSPredicate(format: "label == %@", label)).allElementsBoundByIndex.filter { $0.isHittable }
            if all.count >= 1, let last = all.last {
                last.tap()
                return
            }
            usleep(200_000)
        }
        XCTFail("no dialog button \(label)")
    }

    func toggleOn(_ label: String) {
        let s = wait(app.switches[label].firstMatch)
        if (s.value as? String) != "1" { s.tap() }
        if (s.value as? String) != "1" { s.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap() }
        XCTAssertEqual(s.value as? String, "1")
    }

    func dismissKeyboard() {
        if app.keyboards.count > 0 { app.swipeDown(velocity: .slow) }
    }

    func tab(_ name: String) { app.tabBars.buttons[name].firstMatch.tap() }

    func back() { app.navigationBars.buttons.element(boundBy: 0).tap() }

    func notice(contains text: String) {
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", text)).firstMatch, 8)
    }

    func connect() {
        type(wait(app.textFields["Server address"]), server)
        shot("01-setup")
        button("Connect").tap()
    }

    func register(email: String, name: String, secretKey: Bool) {
        wait(button("Create account")).tap()
        type(app.textFields["Email"], email)
        type(app.textFields["Your name"], name)
        // Confirmation first: in the simulator the first secure field of a sign-up form loses
        // focus after one typed character (system password heuristics), the second one doesn't.
        type(app.secureTextFields["Confirm master password"], password)
        type(app.secureTextFields["Master password"], password)
        if secretKey { toggleOn("secretKeyToggle") }
        shot(secretKey ? "02-register" : "02b-register-second")
        dismissKeyboard()
        wait(button("Create account")).tap()
        if secretKey {
            wait(app.staticTexts["secretKey"], 60)
            shot("03-secret-key")
            toggleOn("savedToggle")
        }
        wait(button("Open my vault"), 60).tap()
        wait(app.navigationBars["Vault"], 60)
    }

    func newItem(_ kind: String) {
        wait(app.buttons["newItem"]).tap()
        wait(button(kind)).tap()
    }

    func unlock() {
        // With Face ID on (and the host sending matches) the vault may open by itself.
        let field = app.secureTextFields["Master password"]
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline && !field.exists && !app.navigationBars["Vault"].exists { usleep(300_000) }
        if app.navigationBars["Vault"].exists { return }
        sleep(1)
        if app.navigationBars["Vault"].exists { return }
        type(wait(field, 30), password)
        button("Unlock").tap()
        wait(app.navigationBars["Vault"], 60)
    }
}

@MainActor
final class PassAuthUITests: UITestBase {
    // MARK: Flows

    func testFullFlow() throws {
        continueAfterFailure = false
        app.launchArguments = ["-PAResetState"]
        app.launch()
        let stamp = Int(Date().timeIntervalSince1970)
        let email = "ios\(stamp)@example.com"

        // Server, account with a Secret Key, signed in straight into the empty vault.
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        shot("01b-sign-in")
        register(email: email, name: "Ada Lovelace", secretKey: true)
        shot("04-vault-empty")

        // New login with a TOTP key and a website.
        newItem("Login")
        type(app.textFields["edit.name"], "GitHub")
        type(app.textFields["edit.username"], "ada@example.com")
        type(app.secureTextFields["edit.password"], "hunter2")
        type(app.textFields["edit.totp"], "JBSWY3DPEHPK3PXP")
        type(app.textFields["edit.url0"], "https://github.com")
        shot("05-edit-login")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View login"], 30)
        wait(app.staticTexts["totpCode"])
        shot("06-item-view")
        app.buttons["copy:Password"].firstMatch.tap()
        notice(contains: "Password copied")

        // Edit it.
        button("Edit").tap()
        replace(app.textFields["edit.name"], "GitHub Work")
        app.buttons["edit.save"].tap()
        wait(app.staticTexts["GitHub Work"], 30)
        back()

        // A secure note and a card.
        newItem("Secure note")
        type(app.textFields["edit.name"], "Wi-Fi at home")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View secure note"], 30)
        back()
        newItem("Card")
        type(app.textFields["edit.name"], "Travel card")
        type(app.textFields["Card number"], "4111111111111111")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View card"], 30)
        back()
        wait(app.staticTexts["Travel card"])
        shot("07-vault-list")

        // Search.
        let search = app.searchFields.firstMatch
        type(search, "wi-fi")
        wait(app.staticTexts["Search results"])
        XCTAssertFalse(app.staticTexts["Travel card"].exists)
        shot("08-search")
        // Leave search mode (the search bar's close button).
        let close = app.navigationBars.buttons["Close"].firstMatch
        if close.exists { close.tap() } else { app.buttons["Cancel"].firstMatch.tap() }

        // Trash and restore.
        wait(app.staticTexts["Travel card"]).tap()
        wait(button("Move to trash")).tap()
        confirm("Move to trash")
        wait(app.navigationBars["Vault"], 30)
        XCTAssertFalse(app.staticTexts["Travel card"].waitForExistence(timeout: 2))
        app.buttons["filters"].tap()
        wait(button("Trash")).tap()
        wait(app.staticTexts["Travel card"]).tap()
        shot("09-trash-item")
        wait(button("Restore")).tap()
        notice(contains: "restored")
        back()
        app.buttons["filters"].tap()
        wait(button("Clear filters")).tap()
        wait(app.staticTexts["Travel card"])

        // Generator.
        tab("Generator")
        let generated = wait(app.staticTexts["generated"])
        let first = generated.label
        button("Regenerate").tap()
        XCTAssertNotEqual(generated.label, first)
        shot("10-generator")
        button("Passphrase").tap()
        shot("10b-passphrase")

        // Settings.
        tab("Settings")
        shot("11-settings")
        app.buttons["settings.security"].tap()
        wait(app.navigationBars["Account security"])
        shot("12-security")
        back()
        app.buttons["settings.autofill"].tap()
        wait(app.navigationBars["AutoFill"])
        shot("13-autofill")
        back()
        app.buttons["settings.about"].tap()
        wait(app.staticTexts["version"])
        shot("14-about")
        back()
        app.buttons["settings.appearance"].tap()
        wait(app.navigationBars["Appearance"])
        shot("14b-appearance")
        wait(button("Dark")).tap()
        back()
        tab("Vault")
        shot("15-vault-dark")
        wait(app.staticTexts["GitHub Work"]).tap()
        shot("16-item-dark")
        back()
        tab("Settings")
        app.buttons["settings.appearance"].tap()
        wait(button("Same as system")).tap()
        back()

        // Lock and unlock.
        app.buttons["settings.security"].tap()
        wait(app.buttons["lockNow"]).tap()
        wait(app.staticTexts["Unlock PassAuth"], 20)
        shot("17-unlock")
        unlock()

        // Vault timeout "Immediately": leaving the app locks it.
        tab("Settings")
        app.buttons["settings.security"].tap()
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("Immediately")).tap()
        XCUIDevice.shared.press(.home)
        sleep(2)
        app.activate()
        wait(app.staticTexts["Unlock PassAuth"], 20)
        unlock()

        // Second account on the same server, then switch back.
        app.buttons["accountMenu"].firstMatch.tap()
        wait(button("Add account")).tap()
        connect()
        register(email: "second\(stamp)@example.com", name: "Grace Hopper", secretKey: false)
        shot("18-second-account")
        app.buttons["accountMenu"].firstMatch.tap()
        shot("19-account-menu")
        wait(app.buttons.containing(NSPredicate(format: "label CONTAINS 'Ada Lovelace'")).firstMatch).tap()
        // Adding an account keeps the first one unlocked: back in its vault directly.
        wait(app.staticTexts["GitHub Work"], 30)
        shot("19b-switched-back")

        // Timeout back to 15 minutes; relaunching the app locks it (keys only in memory).
        tab("Settings")
        app.buttons["settings.security"].tap()
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("15 minutes")).tap()
        app.terminate()
        app.launchArguments = []
        app.launch()
        wait(app.staticTexts["Unlock PassAuth"], 20)
        unlock()
        wait(app.staticTexts["GitHub Work"])
    }

    /// Run with the server stopped, after testFullFlow: the vault opens from the on-device copy.
    func testOfflineOpen() throws {
        continueAfterFailure = false
        app.launch()
        unlock()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'offline'")).firstMatch, 20)
        wait(app.staticTexts["GitHub Work"])
        shot("20-offline")
        wait(app.staticTexts["GitHub Work"]).tap()
        wait(app.staticTexts["totpCode"])
        back()
        newItem("Secure note")
        type(app.textFields["edit.name"], "Offline note")
        app.buttons["edit.save"].tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'offline'")).firstMatch)
        shot("21-offline-save")
    }

    /// Run after testFullFlow with the server up, while the host sends Face ID matches
    /// (`xcrun simctl spawn <sim> notifyutil -p com.apple.BiometricKit_Sim.pearl.match`) and
    /// Face ID is enrolled: biometric unlock, then vault timeout "Never" across a relaunch.
    func testBiometricAndNever() throws {
        continueAfterFailure = false
        app.launch()
        unlock()
        tab("Settings")
        app.buttons["settings.security"].tap()
        let toggle = wait(app.switches["biometricToggle"])
        if (toggle.value as? String) == "1" {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
            notice(contains: "unlock is off")
        }
        toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
        notice(contains: "unlock is on")
        shot("22-face-id-on")
        // Lock; the unlock screen asks for Face ID by itself.
        wait(app.buttons["lockNow"]).tap()
        wait(app.navigationBars["Vault"], 40)
        shot("23-face-id-unlocked")

        // "Never": the vault stays open across an app restart.
        tab("Settings")
        app.buttons["settings.security"].tap()
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("Never")).tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'without the master password'")).firstMatch)
        shot("24-timeout-never")
        app.terminate()
        app.launch()
        wait(app.navigationBars["Vault"], 30)
        wait(app.staticTexts["GitHub Work"])
        // Back to 15 minutes, then log out of this account.
        tab("Settings")
        app.buttons["settings.security"].tap()
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("15 minutes")).tap()
        back()
        wait(app.buttons["settings.account"]).tap()
        shot("25a-account")
        wait(app.buttons["logout"]).tap()
        confirm("Log out")
        // The other account remains and becomes active (locked after the restart).
        wait(app.staticTexts["Unlock PassAuth"], 20)
        shot("25b-after-logout")
    }
}
