import XCTest

/// AutoFill end to end on the simulator: PassAuth turned on in Settings, then Safari on the
/// local test site (tests/e2e/site served on http://localhost:8099) and the throwaway server.
/// Run in order (each step uses the state the previous one left):
///
///   testAF1Setup      fresh account + a login for http://localhost:8099 with a TOTP key
///   testAF2Enable     Settings → General → AutoFill & Passwords → PassAuth on (+ configuration UI)
///   testAF3Fill       Safari: QuickType suggestion → unlock in the extension → fill, code copied
///   testAF4List       Safari: password list (key button), search, fill
///   testAF5Passkeys   Safari: create a passkey with PassAuth, then sign in with it
///   testAF6SaveGenerated   iOS 26.2: sign-up page (tests/e2e/site/ios-signup.html, password rules) →
///                          "Fill Strong Password" (PassAuth's generator) → submit → save sheet → saved
///   testAF7UpdatePassword  typed new password → iOS "Save Password?" → PassAuth → update + history
///   testAF8PassphraseAndNever  no rules + passphrase setting → passphrase filled; "Never for this site"
@MainActor
final class AutoFillUITests: XCTestCase {
    private let env = ProcessInfo.processInfo.environment
    private var server: String { env["PA_SERVER"] ?? "http://127.0.0.1:8091" }
    private let password = "Velvet-Orbit-Canyon-42!"
    private let app = XCUIApplication()
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let settings = XCUIApplication(bundleIdentifier: "com.apple.Preferences")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    private let site = "http://localhost:8099"

    // MARK: Helpers

    private func shot(_ name: String) {
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

    /// Save the accessibility tree of an app (to find system UI elements).
    private func dump(_ a: XCUIApplication, _ name: String) {
        guard let dir = env["PA_SHOTS"] else { return }
        try? a.debugDescription.write(toFile: dir + "/\(name).txt", atomically: true, encoding: .utf8)
    }

    @discardableResult
    private func wait(_ e: XCUIElement, _ timeout: TimeInterval = 20, file: StaticString = #filePath, line: UInt = #line) -> XCUIElement {
        if !e.waitForExistence(timeout: timeout) { shot("fail-af-\(line)") }
        XCTAssertTrue(e.exists, "missing: \(e)", file: file, line: line)
        return e
    }

    private func type(_ e: XCUIElement, _ text: String) {
        wait(e).tap()
        e.typeText(text)
    }

    private func first(_ q: XCUIElementQuery, _ predicate: String, _ args: CVarArg...) -> XCUIElement {
        q.matching(NSPredicate(format: predicate, argumentArray: args)).firstMatch
    }

    private func toggleOn(_ s: XCUIElement) {
        wait(s)
        if (s.value as? String) != "1" { s.tap() }
        if (s.value as? String) != "1" { s.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap() }
    }

    /// The AutoFill extension's UI is shown by a system process; search every candidate.
    private func extensionElement(_ build: (XCUIApplication) -> XCUIElement, timeout: TimeInterval = 20) -> XCUIElement? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            for a in [safari, springboard, settings] {
                let e = build(a)
                if e.exists { return e }
            }
            usleep(300_000)
        }
        return nil
    }

    private func openInSafari(_ path: String) {
        safari.launch()
        let url = URL(string: site + path)!
        safari.open(url)
        wait(safari.webViews.firstMatch, 30)
        sleep(2)
    }

    /// Type the master password into the extension's unlock screen if it is shown.
    private func unlockExtensionIfAsked(_ tag: String) {
        guard let field = extensionElement({ $0.secureTextFields["Master password"] }, timeout: 15) else { return }
        shot("af-\(tag)-unlock")
        sleep(1)
        for _ in 0..<5 {
            field.tap()
            usleep(600_000)
            if (field.value(forKey: "hasKeyboardFocus") as? Bool) == true { break }
        }
        field.typeText(password)
        if let b = extensionElement({ $0.buttons["Unlock"] }, timeout: 5) { b.tap() }
    }

    // MARK: Steps

    func testAF1Setup() throws {
        continueAfterFailure = false
        app.launchArguments = ["-PAResetState", "-PASkipPermissions"]
        app.launch()
        type(wait(app.textFields["Server address"]), server)
        app.buttons["Connect"].firstMatch.tap()
        wait(app.buttons["Create account"].firstMatch).tap()
        type(app.textFields["Email"], "autofill\(Int(Date().timeIntervalSince1970))@example.com")
        type(app.textFields["Your name"], "Alice Fill")
        type(app.secureTextFields["Confirm master password"], password)
        type(app.secureTextFields["Master password"], password)
        if app.keyboards.count > 0 { app.swipeDown(velocity: .slow) }
        wait(app.buttons["Create account"].firstMatch).tap()
        wait(app.buttons["Open my vault"].firstMatch, 60).tap()
        wait(app.navigationBars["Vault"], 60)

        wait(app.buttons["newItem"]).tap()
        wait(app.buttons["Login"].firstMatch).tap()
        type(app.textFields["edit.name"], "Local Test")
        type(app.textFields["edit.username"], "alice@example.com")
        type(app.secureTextFields["edit.password"], "Hunter2-Local!")
        type(app.textFields["edit.totp"], "JBSWY3DPEHPK3PXP")
        type(app.textFields["edit.url0"], site)
        app.buttons["edit.save"].tap()
        wait(app.navigationBars["View login"], 30)
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // AutoFill settings page (not enabled yet).
        app.tabBars.buttons["Settings"].firstMatch.tap()
        app.buttons["settings.autofill"].tap()
        wait(app.navigationBars["AutoFill"])
        sleep(1)
        shot("af-01-settings-off")
    }

    func testAF2Enable() throws {
        continueAfterFailure = false
        settings.launch()
        sleep(2)
        dump(settings, "settings-root")
        // General → AutoFill & Passwords.
        let general = first(settings.buttons, "identifier == 'com.apple.settings.general' OR label == 'General'")
        if !general.exists { settings.swipeUp() }
        wait(general).tap()
        let autofill = first(settings.descendants(matching: .any), "label CONTAINS 'AutoFill'")
        if !autofill.waitForExistence(timeout: 5) { settings.swipeUp() }
        dump(settings, "settings-general")
        wait(autofill).tap()
        sleep(2)
        dump(settings, "settings-autofill")
        shot("af-02-autofill-settings")
        let toggle = first(settings.switches, "label CONTAINS 'PassAuth'")
        wait(toggle)
        // Off first, so turning it on always shows PassAuth's configuration UI.
        if (toggle.value as? String) == "1" {
            toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.93, dy: 0.5)).tap()
            sleep(2)
        }
        toggleOn(toggle)
        sleep(3)
        shot("af-03-configuration")
        dump(springboard, "springboard-after-toggle")
        dump(settings, "settings-after-toggle")
        // ShowsConfigurationUI: PassAuth's configuration sheet asks to unlock, then "AutoFill is ready".
        unlockExtensionIfAsked("config")
        if extensionElement({ $0.staticTexts["AutoFill is ready"] }, timeout: 30) != nil {
            shot("af-04-configured")
            extensionElement({ $0.buttons["autofillCancel"] }, timeout: 5)?.tap()
        }
        sleep(2)
        shot("af-05-enabled")
        XCTAssertEqual(first(settings.switches, "label CONTAINS 'PassAuth'").value as? String, "1")

        // The app shows it as on.
        app.launch()
        if app.secureTextFields["Master password"].waitForExistence(timeout: 5) {
            app.secureTextFields["Master password"].tap()
            app.secureTextFields["Master password"].typeText(password)
            app.buttons["Unlock"].firstMatch.tap()
        }
        wait(app.tabBars.firstMatch, 60)
        app.tabBars.buttons["Settings"].firstMatch.tap()
        app.buttons["settings.autofill"].tap()
        let status = wait(app.descendants(matching: .any)["autofillStatus"].firstMatch)
        let deadline = Date().addingTimeInterval(10)
        while (status.value as? String) != "on" && Date() < deadline { usleep(300_000) }
        shot("af-06-app-settings")
        // The state comes from the system credential identity store, which the iOS 27.0
        // simulator can't reach (launchd_sim has no CredentialProviderExtensionHelper): "off"
        // there. Set PA_IDENTITY_STORE=1 where the store works (devices).
        if env["PA_IDENTITY_STORE"] == "1" { XCTAssertEqual(status.value as? String, "on") }
    }

    private var emailField: XCUIElement { safari.webViews.textFields["Email"].firstMatch }
    private var passwordField: XCUIElement { safari.webViews.secureTextFields["Password"].firstMatch }
    private var codeField: XCUIElement { safari.webViews.textFields["Code"].firstMatch }

    /// Paste the clipboard into the page's code field; returns what landed there.
    private func pasteCode() -> String {
        wait(codeField).tap()
        sleep(1)
        codeField.tap()
        if let paste = extensionElement({ $0.menuItems["Paste"].exists ? $0.menuItems["Paste"] : $0.buttons["Paste"] }, timeout: 5) { paste.tap() }
        sleep(1)
        let v = (codeField.value as? String) ?? ""
        return v == "Paste code here" ? "" : v
    }

    /// QuickType suggestion with the saved user name (from the credential identity store).
    func testAF3Fill() throws {
        // Needs the system credential identity store (see testAF2Enable); not on the simulator.
        try XCTSkipUnless(env["PA_IDENTITY_STORE"] == "1", "QuickType identities need a working credential identity store (device)")
        continueAfterFailure = false
        // Lock the app so the extension has to unlock by itself.
        app.launch()
        app.terminate()
        openInSafari("/ios-login.html")
        shot("af-10-safari-page")
        wait(emailField).tap()
        sleep(2)
        dump(safari, "safari-keyboard")
        shot("af-11-quicktype")
        let suggestion = extensionElement({ first($0.descendants(matching: .any), "label CONTAINS 'alice@example.com'") }, timeout: 10)
        XCTAssertNotNil(suggestion, "QuickType suggestion")
        suggestion?.tap()
        unlockExtensionIfAsked("fill")
        sleep(3)
        shot("af-12-filled")
        XCTAssertEqual(emailField.value as? String, "alice@example.com")
        let code = pasteCode()
        shot("af-13-code-pasted")
        XCTAssertEqual(code.count, 6, "6-digit code pasted, got \(code)")
    }

    /// The "Passwords" button above the keyboard → PassAuth's list → unlock → fill; code copied.
    func testAF4List() throws {
        continueAfterFailure = false
        app.launch()
        app.terminate()
        openInSafari("/ios-login.html")
        wait(emailField).tap()
        sleep(2)
        let key = extensionElement({ $0.buttons["Passwords"] }, timeout: 10)
        XCTAssertNotNil(key, "Passwords button above the keyboard")
        key?.tap()
        sleep(2)
        dump(springboard, "springboard-passwords")
        dump(safari, "safari-passwords")
        shot("af-20-passwords-sheet")
        // iOS may ask which provider to use.
        if extensionElement({ $0.staticTexts["Unlock PassAuth"] }, timeout: 3) == nil,
           let pa = extensionElement({ first($0.buttons, "label CONTAINS 'PassAuth'") }, timeout: 3) {
            pa.tap()
            sleep(2)
        }
        unlockExtensionIfAsked("list")
        let row = extensionElement({ $0.buttons["login-Local Test"] }, timeout: 40)
        sleep(1)
        shot("af-21-list")
        XCTAssertNotNil(row, "PassAuth list with the matching login")
        if let mem = extensionElement({ $0.staticTexts["autofillMemory"] }, timeout: 2) {
            try? mem.label.write(toFile: (env["PA_SHOTS"] ?? NSTemporaryDirectory()) + "/memory-list-unlock.txt", atomically: true, encoding: .utf8)
        }
        if let search = extensionElement({ $0.searchFields.firstMatch }, timeout: 3) {
            search.tap()
            search.typeText("local")
            sleep(1)
            shot("af-22-search")
        }
        extensionElement({ $0.buttons["login-Local Test"] }, timeout: 5)?.tap()
        sleep(3)
        shot("af-23-filled-from-list")
        XCTAssertEqual(emailField.value as? String, "alice@example.com")
        let code = pasteCode()
        shot("af-24-code-pasted")
        XCTAssertEqual(code.count, 6, "6-digit code pasted, got \(code)")
        XCTAssertTrue(code.allSatisfy(\.isNumber))
    }

    func testAF5Passkeys() throws {
        continueAfterFailure = false
        openInSafari("/ios-passkey.html")
        wait(safari.webViews.buttons["Create passkey"]).tap()
        sleep(3)
        dump(springboard, "springboard-passkey-create")
        dump(safari, "safari-passkey-create")
        shot("af-30-passkey-sheet")
        // The system sheet: choose PassAuth / Continue.
        for label in ["Add Passkey", "Continue", "Save Passkey", "Save"] {
            if let b = extensionElement({ first($0.buttons, "label == %@", label) }, timeout: 3) { b.tap(); sleep(2) }
            if extensionElement({ $0.buttons["savePasskey"] }, timeout: 1) != nil || extensionElement({ $0.secureTextFields["Master password"] }, timeout: 1) != nil { break }
        }
        unlockExtensionIfAsked("passkey-create")
        if let save = extensionElement({ $0.buttons["savePasskey"] }, timeout: 20) {
            shot("af-31-save-passkey")
            save.tap()
        }
        let registered = wait(first(safari.webViews.staticTexts, "label BEGINSWITH 'registered'"), 60)
        shot("af-32-registered")
        XCTAssertTrue(registered.label.contains("ok"))
        XCTAssertTrue(registered.label.contains("aaguid=bbc747a14ff929df6533dfaa44f86a18"), registered.label)

        // Sign in with it.
        wait(safari.webViews.buttons["Sign in with passkey"]).tap()
        sleep(3)
        dump(springboard, "springboard-passkey-get")
        dump(safari, "safari-passkey-get")
        shot("af-33-passkey-get-sheet")
        // A saved identity (from the identity store) is offered directly; otherwise "More from PassAuth…"
        // opens PassAuth's list with the passkeys for the site.
        if let identity = extensionElement({ first($0.buttons, "label CONTAINS 'alice@localhost'") }, timeout: 3) {
            identity.tap()
            if let c = extensionElement({ first($0.buttons, "label == 'Continue'") }, timeout: 3) { c.tap() }
        } else if let more = extensionElement({ first($0.buttons, "label CONTAINS 'PassAuth'") }, timeout: 5) {
            more.tap()
            if let c = extensionElement({ first($0.buttons, "label == 'Continue'") }, timeout: 3) { c.tap() }
        }
        unlockExtensionIfAsked("passkey-get")
        if let row = extensionElement({ $0.buttons["passkey-alice@localhost"].firstMatch }, timeout: 20) {
            sleep(1)
            shot("af-33b-passkey-list")
            row.tap()
        }
        let signed = wait(first(safari.webViews.staticTexts, "label BEGINSWITH 'signed in'"), 60)
        shot("af-34-signed-in")
        XCTAssertTrue(signed.label.contains("signed in ok"), signed.label)
        XCTAssertTrue(signed.label.contains("user=user-123"), signed.label)
        XCTAssertTrue(signed.label.contains("sameId=true"), "newest passkey listed first: \(signed.label)")
    }

    // MARK: Saving logins and generating passwords (iOS 26.2 APIs)

    private var newPasswordField: XCUIElement { safari.webViews.secureTextFields["New password"].firstMatch }
    private var confirmField: XCUIElement { safari.webViews.secureTextFields["Confirm password"].firstMatch }

    /// The page's rules (tests/e2e/site/ios-signup.html).
    private func followsSignupRules(_ pw: String) -> Bool {
        (12...18).contains(pw.count) && pw.contains(where: \.isUppercase) && pw.contains(where: \.isLowercase)
            && pw.contains(where: \.isNumber) && pw.contains { "-_.".contains($0) }
            && pw.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-_.".contains($0)) }
    }

    /// Fill the sign-up form's email and focus the new password (iOS shows its strong password panel).
    private func startSignup(_ path: String, email: String) {
        app.launch()
        app.terminate()
        openInSafari(path)
        wait(emailField).tap()
        emailField.typeText(email)
        wait(newPasswordField).tap()
        sleep(3)
    }

    /// Submit, unlock PassAuth's save sheet; returns the revealed password it shows.
    private func submitAndOpenSaveSheet(_ tag: String) -> String {
        // The "New Strong Password" pill can cover the button: close the field's accessory bar first.
        let done = safari.buttons["Done"].firstMatch
        if done.exists && done.isHittable { done.tap(); sleep(1) }
        safari.webViews.buttons["Create account"].firstMatch.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)).tap()
        wait(first(safari.webViews.staticTexts, "label BEGINSWITH 'created'"), 10)
        sleep(3)
        shot("af-\(tag)-after-submit")
        dump(safari, "safari-\(tag)-after-submit")
        dump(springboard, "springboard-\(tag)-after-submit")
        // A typed password: iOS asks "Save Password?" / "Update Password?" with the providers first.
        if extensionElement({ first($0.staticTexts, "label IN {'Save Password?', 'Update Password?'}") }, timeout: 3) != nil,
           let pa = extensionElement({ first($0.buttons, "label == 'PassAuth'") }, timeout: 3) {
            pa.tap()
            sleep(2)
        }
        unlockExtensionIfAsked(tag)
        guard let save = extensionElement({ $0.buttons["saveLogin"] }, timeout: 40) else {
            XCTFail("PassAuth save sheet")
            return ""
        }
        _ = save
        extensionElement({ $0.buttons["Show password"].firstMatch }, timeout: 5)?.tap()
        sleep(1)
        return extensionElement({ $0.descendants(matching: .any)["savePassword"].firstMatch }, timeout: 5)?.value as? String ?? ""
    }

    /// Save / Update in PassAuth's sheet; it closes once the login is stored (sync, write, sync).
    private func tapSaveAndWaitForClose() {
        extensionElement({ $0.buttons["saveLogin"] })?.tap()
        let deadline = Date().addingTimeInterval(30)
        while Date() < deadline, extensionElement({ $0.buttons["saveLogin"] }, timeout: 1) != nil { sleep(1) }
        if extensionElement({ $0.buttons["saveLogin"] }, timeout: 1) != nil {
            shot("fail-save-sheet-open")
            dump(safari, "safari-save-sheet-open")
            XCTFail("sheet still open: \(extensionElement({ $0.staticTexts["error"] }, timeout: 1)?.label ?? "no error shown")")
        }
    }

    private func openItemInApp(_ name: String, user: String) {
        app.launch()
        if app.secureTextFields["Master password"].waitForExistence(timeout: 5) {
            app.secureTextFields["Master password"].tap()
            app.secureTextFields["Master password"].typeText(password)
            app.buttons["Unlock"].firstMatch.tap()
        }
        wait(app.tabBars.firstMatch, 60)
        app.tabBars.buttons["Vault"].firstMatch.tap()
        // testAF5Passkeys also leaves a login named "localhost": pick the row with the user name.
        wait(first(app.buttons, "identifier == %@ AND label CONTAINS %@", "item:\(name)", user), 30).tap()
        wait(app.navigationBars["View login"], 20)
        sleep(1)
    }

    /// iOS 26.2 password generation + saving: "Fill Strong Password" fills PassAuth's password
    /// (no unlock: the vault isn't needed), following the page's password rules; submitting the
    /// form brings up PassAuth's save sheet (unlock → "Save this login?"); the login is in the app.
    func testAF6SaveGenerated() throws {
        continueAfterFailure = false
        startSignup("/ios-signup.html", email: "signup@example.com")
        shot("af-40-strong-password-panel")
        XCTAssertNotNil(extensionElement({ $0.buttons["Save in PassAuth"] }, timeout: 5), "iOS offers PassAuth as the place to save")
        wait(safari.buttons["GenerateStrongPasswordButton"].firstMatch).tap()
        sleep(3)
        shot("af-41-strong-password-filled")
        XCTAssertNil(extensionElement({ $0.secureTextFields["Master password"] }, timeout: 2), "generating needs no unlock")
        let revealed = submitAndOpenSaveSheet("save")
        shot("af-42-save-sheet")
        let status = first(safari.webViews.staticTexts, "label BEGINSWITH 'created'").label
        XCTAssertEqual(status, "created signup@example.com / \(revealed.count) chars")
        XCTAssertTrue(followsSignupRules(revealed), "PassAuth's generator with the page's rules: \(revealed)")
        XCTAssertEqual(extensionElement({ $0.descendants(matching: .any)["saveUser"].firstMatch })?.value as? String, "signup@example.com")
        tapSaveAndWaitForClose()
        shot("af-43-saved")

        openItemInApp("localhost", user: "signup@example.com")
        shot("af-44-saved-login-in-app")
        XCTAssertTrue(first(app.staticTexts, "label == 'signup@example.com'").exists)
        try revealed.write(toFile: (env["PA_SHOTS"] ?? NSTemporaryDirectory()) + "/af6-password.txt", atomically: true, encoding: .utf8)
    }

    /// Changing the password of a saved login: "Update the password?" → the old one is in the history.
    func testAF7UpdatePassword() throws {
        continueAfterFailure = false
        startSignup("/ios-signup.html", email: "signup@example.com")
        // Close the strong password panel and type a password of our own.
        safari.buttons.matching(identifier: "xmark").firstMatch.tap()
        sleep(1)
        newPasswordField.tap()
        newPasswordField.typeText("Changed-Pass_456")
        wait(confirmField).tap()
        confirmField.typeText("Changed-Pass_456")
        let revealed = submitAndOpenSaveSheet("update")
        XCTAssertEqual(revealed, "Changed-Pass_456")
        XCTAssertNotNil(extensionElement({ $0.staticTexts["Update the password?"] }, timeout: 5))
        shot("af-50-update-sheet")
        tapSaveAndWaitForClose()

        openItemInApp("localhost", user: "signup@example.com")
        let history = app.buttons["passwordHistory"]
        for _ in 0..<4 where !history.isHittable { app.swipeUp() }
        wait(history).tap()
        wait(app.navigationBars["Password history"])
        app.buttons["Show password 1"].firstMatch.tap()
        sleep(1)
        shot("af-51-password-history")
        let old = (try? String(contentsOfFile: (env["PA_SHOTS"] ?? NSTemporaryDirectory()) + "/af6-password.txt", encoding: .utf8)) ?? ""
        if !old.isEmpty { XCTAssertTrue(first(app.staticTexts, "label == %@", old).exists, "generated password in the history") }
    }

    /// Without site rules the generator's settings apply (here: passphrase preferred); "Never
    /// for this site" puts the base domain on the list in Settings → AutoFill.
    func testAF8PassphraseAndNever() throws {
        continueAfterFailure = false
        app.launch()
        if app.secureTextFields["Master password"].waitForExistence(timeout: 5) {
            app.secureTextFields["Master password"].tap()
            app.secureTextFields["Master password"].typeText(password)
            app.buttons["Unlock"].firstMatch.tap()
        }
        wait(app.tabBars.firstMatch, 60)
        app.tabBars.buttons["Generator"].firstMatch.tap()
        wait(app.buttons["Passphrase"].firstMatch).tap()
        sleep(2)
        startSignup("/ios-signup.html?norules", email: "phrase@example.com")
        // The suggestion pill (user-initiated generation).
        if let pill = extensionElement({ first($0.descendants(matching: .any), "label == 'New Strong Password'") }, timeout: 3) {
            pill.tap()
            sleep(3)
            shot("af-60-after-pill-tap")
            dump(safari, "safari-after-pill")
            dump(springboard, "springboard-after-pill")
        }
        if let ui = extensionElement({ $0.buttons["useGenerated"] }, timeout: 3) {
            shot("af-61-generate-sheet")
            ui.tap()
        } else {
            wait(safari.buttons["GenerateStrongPasswordButton"].firstMatch).tap()
        }
        sleep(3)
        shot("af-62-passphrase-filled")
        let revealed = submitAndOpenSaveSheet("phrase")
        shot("af-63-save-sheet-passphrase")
        let words = revealed.split(separator: "-")
        XCTAssertEqual(words.count, 5, "passphrase with the default 5 words: \(revealed)")
        XCTAssertTrue(words.allSatisfy { $0.first?.isUppercase == true })
        extensionElement({ $0.buttons["saveNever"] })?.tap()
        sleep(3)
        XCTAssertNil(extensionElement({ $0.buttons["saveLogin"] }, timeout: 2))

        app.launch()
        if app.secureTextFields["Master password"].waitForExistence(timeout: 5) {
            app.secureTextFields["Master password"].tap()
            app.secureTextFields["Master password"].typeText(password)
            app.buttons["Unlock"].firstMatch.tap()
        }
        wait(app.tabBars.firstMatch, 60)
        app.tabBars.buttons["Generator"].firstMatch.tap()
        wait(app.buttons["Password"].firstMatch).tap()
        app.tabBars.buttons["Settings"].firstMatch.tap()
        app.buttons["settings.autofill"].tap()
        let row = app.descendants(matching: .any)["neverSave-localhost"].firstMatch
        for _ in 0..<4 where !row.exists { app.swipeUp() }
        wait(row)
        shot("af-64-never-save-list")
        XCTAssertEqual(app.switches["settings.askToSave"].value as? String, "1")
        app.buttons["Remove localhost"].tap()
        sleep(1)
        XCTAssertFalse(row.exists)
        shot("af-65-never-save-removed")
    }
}
