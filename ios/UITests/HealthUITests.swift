import XCTest

/// Settings → Password health against the throwaway server (debug builds): weak and reused
/// logins listed, a row opening the login's editor, the notes on an item's page, the page at
/// Accessibility XXL, and the breach check with the app's stub range API (`-PAStubBreachCheck`:
/// never Have I Been Pwned itself) whose results are gone after locking.
@MainActor
final class HealthUITests: UITestBase {
    /// Two logins sharing the weak password "sunshine1", one more weak one, one strong one.
    private func signedIn(_ prefix: String, large: Bool = false, stub: Bool = false) async throws {
        let email = "\(prefix)-\(Int(Date().timeIntervalSince1970))@example.com"
        let srv = TestServer(server)
        try await srv.register(email: email, password: password, name: "Ada Lovelace")
        let helper = try await srv.login(email: email, password: password)
        for (name, user, secret, url) in [
            ("Shop", "ada@example.com", "sunshine1", "https://shop.example.com"),
            ("Mail", "ada@example.com", "sunshine1", "https://mail.example.com"),
            ("Forum", "ada", "qwerty", "https://forum.example.org"),
            ("Bank", "ada.l", "Lumen-Quartz-Harbor-77!", "https://bank.example.com"),
        ] {
            try await srv.createItem(helper, [
                "name": name, "notes": "", "favorite": false, "fields": [], "created_at": 1_700_000_000, "updated_at": 1_700_000_000,
                "login": ["username": user, "password": secret, "urls": [["url": url]]],
            ])
        }
        app.launchArguments = ["-PAResetState", "-PASkipPermissions"]
            + (large ? ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXL"] : [])
            + (stub ? ["-PAStubBreachCheck"] : [])
        app.launch()
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        wait(app.navigationBars["Vault"], 60)
        // iOS's own "Save Password?" sheet for the sign-in form.
        let board = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for candidate in [board.buttons["Not Now"].firstMatch, app.buttons["Not Now"].firstMatch] where candidate.waitForExistence(timeout: 3) {
            candidate.tap()
            break
        }
    }

    /// A tab, also where the tab bar's items are exposed as plain buttons (floating tab bar).
    private func show(_ name: String) {
        let item = app.tabBars.buttons[name].firstMatch
        if item.waitForExistence(timeout: 3) { item.tap() } else { wait(app.buttons[name].firstMatch).tap() }
    }

    private func openHealth() {
        show("Settings")
        let entry = app.buttons["settings.health"]
        wait(entry).tap()
        wait(app.navigationBars["Password health"])
    }

    private func element(_ label: String) -> XCUIElement { app.descendants(matching: .any)[label].firstMatch }

    private func scrollTo(_ e: XCUIElement, max: Int = 10) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    func testPasswordHealth() async throws {
        continueAfterFailure = false
        try await signedIn("health")
        openHealth()
        // The summary: 2 logins share a password, 3 are weak, 4 have one; not checked yet.
        wait(element("Reused: 2"))
        wait(element("Weak: 3"))
        wait(element("Logins with a password: 4"))
        wait(element("Exposed: not checked yet"))
        wait(app.buttons["health.check"])
        shot("health-01-page")

        // Reused group, then the weak list: the strong login is in neither.
        scrollTo(element("Same password in 2 logins"))
        shot("health-02-reused")
        let weakForum = app.buttons["health.row:Forum"].firstMatch
        scrollTo(weakForum)
        shot("health-03-weak")
        XCTAssertFalse(app.buttons["health.row:Bank"].exists)

        // A row opens the login's editor; leaving it comes back here.
        weakForum.tap()
        wait(app.secureTextFields["edit.password"], 10)
        shot("health-04-editor")
        button("Cancel").tap()
        wait(app.navigationBars["Password health"])

        // The item page says why: weak and used by another login.
        show("Vault")
        wait(app.staticTexts["Shop"].firstMatch).tap()
        wait(app.navigationBars["View login"], 30)
        let notes = wait(app.descendants(matching: .any)["passwordNotes"].firstMatch)
        XCTAssertEqual(notes.label, "Password health: Weak password, Used in 1 other login")
        wait(button("Change password"))
        shot("health-05-item-notes")
        back()
        wait(app.staticTexts["Bank"].firstMatch).tap()
        wait(app.navigationBars["View login"], 30)
        XCTAssertFalse(app.descendants(matching: .any)["passwordNotes"].exists)
    }

    func testBreachCheckAndLock() async throws {
        continueAfterFailure = false
        try await signedIn("health-check", stub: true)
        openHealth()
        wait(app.buttons["health.check"]).tap()
        // "sunshine1" (Shop, Mail) and "qwerty" (Forum) are in the stub's breaches.
        wait(element("Exposed: 3"), 30)
        shot("health-06-checked")
        let forum = app.buttons["health.row:Forum"].firstMatch
        wait(forum)
        XCTAssertTrue(forum.label.contains("Seen 3,946,737 times"), forum.label)
        let again = app.buttons["health.checkAgain"]
        scrollTo(again)
        XCTAssertTrue(again.exists)
        shot("health-07-checked-bottom")

        show("Vault")
        wait(app.staticTexts["Forum"].firstMatch).tap()
        wait(app.navigationBars["View login"], 30)
        XCTAssertEqual(wait(app.descendants(matching: .any)["passwordNotes"].firstMatch).label, "Password health: Weak password, Found in a data breach")
        shot("health-08-item-breached")
        back()

        // Locking drops the results: after unlocking, the check hasn't run.
        wait(app.buttons["accountMenu"]).tap()
        wait(button("Lock")).tap()
        unlock()
        openHealth()
        wait(element("Exposed: not checked yet"))
        XCTAssertTrue(app.buttons["health.check"].exists)
    }

    func testPasswordHealthLargeText() async throws {
        continueAfterFailure = false
        try await signedIn("health-big", large: true)
        openHealth()
        wait(element("Reused: 2"))
        shot("health-big-01-page")
        app.swipeUp(velocity: .slow)
        shot("health-big-02")
        scrollTo(app.buttons["health.row:Forum"].firstMatch)
        shot("health-big-03-rows")
    }
}
