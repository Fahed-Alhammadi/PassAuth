import XCTest

/// Phase 3 against the throwaway server (debug builds): two-step sign-in, password history,
/// move item, vault filter, live sync, edit conflict, delete forever, TOTP from an image,
/// web vault shortcuts, export, delete account; plus large text screenshots.
///
/// `testPhase3Flow` picks a QR code from Photos: add one first with
/// `xcrun simctl addmedia booted <otpauth QR png>`. It saves the export to "On My iPhone":
/// delete an earlier `passauth-export-*` there first (the replace alert is out of process).
@MainActor
final class Phase3UITests: UITestBase {
    private func signIn(_ email: String, totp: (() throws -> String)? = nil) throws {
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        if let totp {
            wait(app.staticTexts["Two-step login"], 60)
            let code = try totp()
            type(app.textFields["6-digit code"], code)
            shot("p3-01-two-step")
            dismissKeyboard()
            button("Verify and sign in").tap()
        }
        wait(app.navigationBars["Vault"], 60)
    }

    private func scrollTo(_ e: XCUIElement, max: Int = 8) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    private func settingsPage(_ id: String) {
        tab("Settings")
        // Back to the category list if a page is still open.
        while !app.buttons["settings.\(id)"].exists && app.navigationBars.buttons.count > 0 && !app.navigationBars["Settings"].exists { back() }
        wait(app.buttons["settings.\(id)"]).tap()
    }

    func testPhase3Flow() async throws {
        continueAfterFailure = false
        let stamp = Int(Date().timeIntervalSince1970)
        let email = "p3-\(stamp)@example.com"
        let srv = TestServer(server)
        try await srv.register(email: email, password: password, name: "Mary Shelley")
        let helper = try await srv.login(email: email, password: password)
        try await srv.createVault(helper, name: "Team")
        let secret = try await srv.enableTotp(helper)

        app.launchArguments = ["-PAResetState", "-PASkipPermissions"]
        app.launch()
        try signIn(email, totp: { try srv.nextCode(secret) })
        shot("p3-02-vault")

        // A login whose password changes: the old one goes to the password history.
        newItem("Login")
        type(app.textFields["edit.name"], "Shop")
        type(app.textFields["edit.username"], "mary@example.com")
        type(app.secureTextFields["edit.password"], "first-Pass-111")
        // TOTP: no camera in the simulator; a QR code picked from Photos instead.
        dismissKeyboard()
        let scan = app.buttons["totp.scan"]
        scrollTo(scan)
        scan.tap()
        notice(contains: "No camera found")
        app.buttons["totp.image"].tap()
        // The picker runs out of process (its contents aren't in the app's element tree):
        // wait for it to load, then tap the first cell (the newest photo, the QR code added
        // with simctl addmedia). Retried once if the library was still loading.
        let added = app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'Authenticator key added'")).firstMatch
        for attempt in 0..<3 where !added.exists {
            sleep(attempt == 0 ? 8 : 5)
            if attempt == 0 { shot("p3-03-photos-picker") }
            if !app.buttons["totp.image"].isHittable {
                app.coordinate(withNormalizedOffset: CGVector(dx: 0.165, dy: 0.445)).tap()
            }
            _ = added.waitForExistence(timeout: 5)
        }
        XCTAssertTrue(added.exists || (app.textFields["edit.totp"].value as? String ?? "").hasPrefix("otpauth://"), "key read from the QR image")
        shot("p3-04-edit-totp")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View login"], 30)
        button("Edit").tap()
        replace(app.secureTextFields["edit.password"], "second-Pass-222")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View login"], 30)
        let history = app.buttons["passwordHistory"]
        scrollTo(history)
        shot("p3-05-item-history-row")
        wait(history).tap()
        wait(app.navigationBars["Password history"])
        XCTAssertFalse(app.staticTexts["first-Pass-111"].exists)
        shot("p3-06-password-history")
        button("Show password 1").tap()
        wait(app.staticTexts["first-Pass-111"])
        button("Copy password 1").tap()
        notice(contains: "Previous password copied")
        shot("p3-07-password-history-revealed")
        back()

        // Move to the second vault.
        let move = app.buttons["moveItem"]
        scrollTo(move)
        wait(move).tap()
        wait(app.navigationBars["Move item"])
        wait(app.buttons["vault:Team"]).tap()
        shot("p3-08-move-sheet")
        app.buttons["move.confirm"].tap()
        notice(contains: "Moved to Team")
        app.swipeDown(velocity: .fast)
        wait(app.staticTexts.containing(NSPredicate(format: "label == 'Vault: Team'")).firstMatch)
        shot("p3-09-moved")
        back()

        // Vault filter with two vaults.
        wait(app.buttons["filters"]).tap()
        wait(button("Vault")).tap()
        wait(button("Team")).tap()
        wait(app.staticTexts["Filtered items"])
        wait(app.staticTexts["Shop"])
        shot("p3-10-filter-vault")
        app.buttons["filters"].tap()
        wait(button("Vault")).tap()
        wait(button("Personal")).tap()
        XCTAssertFalse(app.staticTexts["Shop"].waitForExistence(timeout: 2))
        app.buttons["filters"].tap()
        wait(button("Clear filters")).tap()

        // Live sync: another device renames the item; the list follows without a refresh.
        sleep(3)
        try await srv.editItem(helper, named: "Shop") { $0["name"] = "Shop (live)" }
        wait(app.staticTexts["Shop (live)"], 20)
        shot("p3-11-live-sync")

        // Edit conflict: the item changes on the server while the editor is open.
        app.staticTexts["Shop (live)"].tap()
        wait(button("Edit")).tap()
        replace(app.textFields["edit.name"], "Shop mine")
        try await srv.editItem(helper, named: "Shop (live)") { $0["notes"] = "changed elsewhere" }
        sleep(2)
        app.buttons["edit.save"].tap()
        wait(app.staticTexts["This item was changed on another device"], 20)
        shot("p3-12-conflict")
        button("Keep my version").tap()
        wait(app.navigationBars["View login"], 30)
        wait(app.staticTexts["Shop mine"], 20)
        back()

        // Delete forever from the trash.
        newItem("Secure note")
        type(app.textFields["edit.name"], "Old note")
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View secure note"], 30)
        let trash = button("Move to trash")
        scrollTo(trash)
        trash.tap()
        confirm("Move to trash")
        wait(app.navigationBars["Vault"], 30)
        app.buttons["filters"].tap()
        wait(button("Trash")).tap()
        wait(app.staticTexts["Old note"].firstMatch).tap()
        let purge = button("Delete forever")
        scrollTo(purge)
        purge.tap()
        shot("p3-13-delete-forever")
        confirm("Delete forever")
        notice(contains: "Item deleted")
        wait(app.staticTexts["The trash is empty."], 20)
        app.buttons["filters"].tap()
        wait(button("Clear filters")).tap()

        // Web vault shortcuts open the server in Safari with path routes.
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        for (page, title, path) in [("security", "Two-step login", "/settings/two-step"), ("security", "Change master password", "/settings/security"),
                                    ("vault", "Vaults & sharing", "/settings/vaults"), ("vault", "Import items", "/import"), ("vault", "Open web vault", "/vault")] {
            settingsPage(page)
            let link = app.buttons.containing(NSPredicate(format: "label BEGINSWITH %@", title)).firstMatch
            scrollTo(link)
            wait(link).tap()
            XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 20), "Safari opened for \(path)")
            if path == "/settings/two-step" {
                sleep(3)
                shot("p3-14-web-vault-safari")
            }
            app.activate()
            wait(app.tabBars.firstMatch, 20)
        }

        // Export (vault timeout "Immediately": the file exporter must not lock the vault).
        settingsPage("security")
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("Immediately")).tap()
        settingsPage("vault")
        wait(app.buttons["settings.export"]).tap()
        wait(app.navigationBars["Export vault"])
        shot("p3-15-export")
        type(app.secureTextFields["export.password"], "export-pass-123")
        type(app.secureTextFields["export.confirm"], "export-pass-123")
        type(app.secureTextFields["export.master"], password)
        dismissKeyboard()
        let run = app.buttons["export.run"]
        scrollTo(run)
        run.tap()
        let save = app.buttons.matching(NSPredicate(format: "label == 'Save' OR label == 'Move'")).firstMatch
        wait(save, 60)
        shot("p3-16-file-exporter")
        save.tap()
        // A file of that name from an earlier run.
        notice(contains: "Vault exported")
        XCTAssertFalse(app.staticTexts["Unlock PassAuth"].exists, "the exporter didn't lock the vault")
        shot("p3-17-exported")
        // The unencrypted formats warn first.
        wait(app.buttons["export.format"]).tap()
        wait(button("JSON (not encrypted)")).tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'not encrypted. Anyone'")).firstMatch)
        shot("p3-18-export-json-warning")
        settingsPage("security")
        wait(app.buttons["vaultTimeout"]).tap()
        wait(button("15 minutes")).tap()

        // Delete account: master password checked by the server, then the account is gone.
        settingsPage("about")
        let del = app.buttons["deleteAccount"]
        scrollTo(del)
        shot("p3-19-about-delete")
        del.tap()
        wait(app.navigationBars["Delete account"])
        type(app.secureTextFields["delete.password"], "wrong-password-1")
        dismissKeyboard()
        app.buttons["delete.confirm"].tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'Wrong master password'")).firstMatch, 60)
        shot("p3-20-delete-wrong-password")
        replace(app.secureTextFields["delete.password"], password)
        dismissKeyboard()
        app.buttons["delete.confirm"].tap()
        wait(app.staticTexts["Sign in to PassAuth"], 60)
        notice(contains: "account has been deleted")
        shot("p3-21-deleted")
        let exists = await srv.accountExists(email: email, password: password)
        XCTAssertFalse(exists, "the account is gone from the server")
    }

    /// Screens at the largest accessibility text size (screenshots to check for clipping).
    func testLargeText() async throws {
        continueAfterFailure = false
        let stamp = Int(Date().timeIntervalSince1970)
        let email = "big-\(stamp)@example.com"
        let srv = TestServer(server)
        try await srv.register(email: email, password: password, name: "Ada Large")
        let helper = try await srv.login(email: email, password: password)
        try await srv.createVault(helper, name: "Team")
        try await srv.createItem(helper, [
            "name": "GitHub", "notes": "", "favorite": true, "fields": [], "created_at": stamp, "updated_at": stamp,
            "login": ["username": "ada@example.com", "password": "second-Pass-222", "totp": "JBSWY3DPEHPK3PXP", "urls": [["url": "https://github.com"]]],
            "password_history": [["password": "first-Pass-111", "changed_at": stamp - 3600]],
        ])
        app.launchArguments = ["-PAResetState", "-PASkipPermissions", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXL"]
        app.launch()
        try signIn(email)
        shot("big-01-vault")
        wait(app.staticTexts["GitHub"].firstMatch).tap()
        wait(app.navigationBars["View login"], 30)
        shot("big-02-item")
        app.swipeUp(velocity: .slow)
        shot("big-03-item-bottom")
        let history = app.buttons["passwordHistory"]
        scrollTo(history)
        wait(history).tap()
        wait(app.navigationBars["Password history"])
        shot("big-04-password-history")
        back()
        let move = app.buttons["moveItem"]
        scrollTo(move)
        wait(move).tap()
        shot("big-05-move")
        button("Cancel").tap()
        app.swipeDown(velocity: .fast)
        app.swipeDown(velocity: .fast)
        wait(button("Edit")).tap()
        let totp = app.textFields["edit.totp"]
        scrollTo(totp, max: 6)
        app.swipeUp(velocity: .slow)
        shot("big-06-edit-totp")
        button("Cancel").tap()
        back()
        settingsPage("vault")
        shot("big-07-vault-options")
        wait(app.buttons["settings.export"]).tap()
        shot("big-08-export")
        app.swipeUp(velocity: .slow)
        shot("big-09-export-bottom")
        settingsPage("about")
        let del = app.buttons["deleteAccount"]
        scrollTo(del)
        shot("big-10-about")
        del.tap()
        wait(app.navigationBars["Delete account"])
        shot("big-11-delete")
        back()
        settingsPage("security")
        app.swipeUp(velocity: .slow)
        shot("big-12-security")
    }
}
