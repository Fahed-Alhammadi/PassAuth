import PassAuthCore
import XCTest

/// Send, attachments and emergency access against the throwaway server (debug builds). The test
/// acts as the other people through the server's API with the Rust core (`TestServer`): Bea, the
/// contact the app's account names, and Cy, who names the app's account.
///
/// Needs a photo in the simulator's library (`xcrun simctl addmedia`), as `Phase3UITests` does.
@MainActor
final class SendAttachmentEmergencyUITests: UITestBase {
    private func scrollTo(_ e: XCUIElement, max: Int = 10) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    /// The tab bar's button (iOS 27 may not list a tab bar element).
    private func goTo(_ name: String) {
        let t = app.tabBars.buttons[name].firstMatch
        if t.waitForExistence(timeout: 3) { t.tap() } else { wait(app.buttons[name].firstMatch).tap() }
    }

    private func settingsPage(_ id: String) {
        goTo("Settings")
        while !app.buttons["settings.\(id)"].exists && app.navigationBars.buttons.count > 0 && !app.navigationBars["Settings"].exists { back() }
        scrollTo(app.buttons["settings.\(id)"])
        wait(app.buttons["settings.\(id)"]).tap()
    }

    private func pullToRefresh() {
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
        start.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)))
        sleep(2)
    }

    /// A button in the emergency list, after refreshing until it shows.
    private func emergencyButton(_ label: String) -> XCUIElement {
        let b = app.buttons[label].firstMatch
        for _ in 0..<6 where !b.exists {
            pullToRefresh()
        }
        scrollTo(b)
        return wait(b, 10)
    }

    private func signIn(_ email: String) {
        connect()
        wait(app.staticTexts["Sign in to PassAuth"], 20)
        type(app.textFields["Email"], email)
        type(app.secureTextFields["Master password"], password)
        dismissKeyboard()
        button("Sign in").tap()
        wait(app.navigationBars["Vault"], 60)
        let board = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for candidate in [board.buttons["Not Now"].firstMatch, app.buttons["Not Now"].firstMatch] where candidate.waitForExistence(timeout: 3) {
            candidate.tap()
            break
        }
    }

    private func item(_ name: String, password: String) -> [String: Any] {
        ["name": name, "notes": "", "favorite": false, "fields": [], "created_at": 1_700_000_000, "updated_at": 1_700_000_000,
         "login": ["username": "ada", "password": password, "urls": [["url": "https://example.com"]]]]
    }

    private func userId(_ srv: TestServer, _ s: TestServer.Session) async throws -> String {
        let sync = try await srv.call("GET", "/sync", session: s)
        return (sync["user"] as? [String: Any])?["id"] as? String ?? ""
    }

    /// The account's own vault and its key, as another device opens them.
    private func ownVault(_ srv: TestServer, _ s: TestServer.Session) async throws -> (id: String, epoch: Int, key: VaultKey, items: [[String: Any]]) {
        let sync = try await srv.call("GET", "/sync", session: s)
        let v = (sync["vaults"] as! [[String: Any]]).first { $0["role"] as? String == "owner" }!
        let id = v["id"] as! String
        let key = try s.account.openVaultKey(vaultId: id, wrapped: v["wrapped_key"] as! String, kind: v["key_kind"] as! String,
                                         keyEpoch: UInt64(v["key_epoch"] as? Int ?? 0), legacyAllowed: true)
        let items = (sync["items"] as? [[String: Any]] ?? []).filter { $0["vault_id"] as? String == id }
        return (id, v["key_epoch"] as? Int ?? 0, key, items)
    }

    private func names(_ key: VaultKey, _ rows: [[String: Any]], vault: String) -> [String] {
        rows.compactMap { r in
            guard let k = r["item_key"] as? String, let d = r["data"] as? String,
                  let json = try? key.decryptItem(encrypted: EncryptedItem(id: r["id"] as! String, vaultId: vault, key: k, data: d)) else { return nil }
            return (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])?["name"] as? String
        }
    }

    func testSendAttachmentsAndEmergencyAccess() async throws {
        continueAfterFailure = false
        let stamp = Int(Date().timeIntervalSince1970)
        let ada = "ada-\(stamp)@example.com"
        let bea = "bea-\(stamp)@example.com"
        let cy = "cy-\(stamp)@example.com"
        let srv = TestServer(server)
        try await srv.register(email: ada, password: password, name: "Ada Lovelace")
        try await srv.register(email: bea, password: password, name: "Bea Contact")
        try await srv.register(email: cy, password: password, name: "Cy Grantor")
        let adaHelper = try await srv.login(email: ada, password: password)
        try await srv.createItem(adaHelper, item("Passport", password: "Ada-Passport-123"))

        app.launchArguments = ["-PAResetState"]
        app.launch()
        signIn(ada)

        // MARK: Send: create, copy the link, open it in the web vault page in Safari.
        settingsPage("send")
        wait(app.navigationBars["Send"])
        wait(app.buttons["send.new"]).tap()
        type(app.textFields["send.name"], "Wi-Fi at home")
        let text = app.textViews["send.text"]
        wait(text).tap()
        text.typeText("router-pass-4711")
        dismissKeyboard()
        shot("se-01-new-send")
        app.buttons["send.save"].tap()
        wait(app.staticTexts["Send created"], 30)
        let linkText = wait(app.staticTexts["send.link"])
        XCTAssertFalse(linkText.label.contains("#") && linkText.label.count > 60, "the key is hidden at first")
        button("Show the key").tap()
        let link = app.staticTexts["send.link"].label
        XCTAssertTrue(link.hasPrefix("\(server)/send/"), link)
        shot("se-02-created")
        app.buttons["send.copyLink"].tap()
        notice(contains: "Link copied")
        button("Done").tap()
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'Wi-Fi at home'")).firstMatch, 20)
        shot("se-03-list")

        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        safari.open(URL(string: link)!)
        let open = safari.buttons["Open text"].firstMatch
        XCTAssertTrue(open.waitForExistence(timeout: 30), "web vault Send page")
        open.tap()
        XCTAssertTrue(safari.staticTexts["router-pass-4711"].firstMatch.waitForExistence(timeout: 30), "decrypted text in the web page")
        XCTAssertTrue(safari.staticTexts["Wi-Fi at home"].firstMatch.exists)
        shot("se-04-web-send")
        safari.terminate()
        app.activate()

        // MARK: Attachments: add a photo, download it, remove it.
        goTo("Vault")
        while !app.navigationBars["Vault"].exists && app.navigationBars.buttons.count > 0 { back() }
        wait(app.buttons["item:Passport"].firstMatch, 30).tap()
        let add = app.buttons["attachments.addPhoto"]
        scrollTo(add)
        wait(add).tap()
        // The picker runs out of process: tap the first cell once it loaded (as Phase3UITests).
        let download = app.buttons["attachments.download"].firstMatch
        for attempt in 0..<3 where !download.exists {
            sleep(attempt == 0 ? 8 : 5)
            if attempt == 0 { shot("se-05-photos-picker") }
            if !add.isHittable { app.coordinate(withNormalizedOffset: CGVector(dx: 0.165, dy: 0.445)).tap() }
            _ = download.waitForExistence(timeout: 30)
        }
        scrollTo(download)
        XCTAssertTrue(download.exists, "file listed after the upload")
        shot("se-06-attached")
        download.tap()
        let share = app.otherElements["ActivityListView"].firstMatch
        let shareShown = share.waitForExistence(timeout: 30) || app.navigationBars["UIActivityContentView"].waitForExistence(timeout: 5)
        shot("se-07-share-sheet")
        XCTAssertTrue(shareShown, "the system share sheet with the decrypted file")
        let closeShare = app.buttons["Close"].firstMatch
        if closeShare.exists { closeShare.tap() } else { app.swipeDown(velocity: .fast) }
        sleep(1)
        let helperSync = try await ownVault(srv, adaHelper)
        let passportRow = helperSync.items.first!
        let stored = try await srv.call("GET", "/items/\(passportRow["id"] as! String)/attachments", session: adaHelper)
        XCTAssertEqual((stored["attachments"] as? [[String: Any]])?.first?["state"] as? String, "ready")
        wait(app.buttons["attachments.remove"].firstMatch).tap()
        confirm("Remove file")
        notice(contains: "File removed")
        XCTAssertFalse(app.buttons["attachments.download"].firstMatch.waitForExistence(timeout: 3))
        let after = try await srv.call("GET", "/items/\(passportRow["id"] as! String)/attachments", session: adaHelper)
        XCTAssertEqual((after["attachments"] as? [[String: Any]])?.count, 0, "file deleted on the server")
        back()

        // MARK: Emergency access, Ada names Bea.
        settingsPage("emergency")
        wait(app.navigationBars["Emergency access"])
        wait(app.buttons["emergency.add"], 30).tap()
        type(app.textFields["emergency.email"], bea)
        dismissKeyboard()
        shot("se-08-add-contact")
        app.buttons["emergency.confirm"].tap()
        notice(contains: "was invited")
        let beaSession = try await srv.login(email: bea, password: password)
        let beaList = try await srv.call("GET", "/emergency-access", session: beaSession)
        let grant = (beaList["as_grantee"] as! [[String: Any]]).first!
        let grantId = grant["id"] as! String
        try await srv.call("POST", "/emergency-access/\(grantId)/accept", session: beaSession)

        emergencyButton("Check and confirm…").tap()
        let fp = try fingerprint(publicKey: beaSession.account.publicKey())
        let row = wait(app.descendants(matching: .any)["invitation.fingerprint"].firstMatch, 10)
        let spoken = fp.split(separator: "-").map { $0.map(String.init).joined(separator: " ") }.joined(separator: ", ")
        XCTAssertTrue(row.label.contains(spoken), "Bea's fingerprint shown: \(row.label)")
        shot("se-09-confirm")
        app.buttons["emergency.confirm"].tap()
        notice(contains: "is your emergency contact now")

        try await srv.call("POST", "/emergency-access/\(grantId)/request", session: beaSession)
        emergencyButton("Approve now…").tap()
        type(app.secureTextFields["emergency.password"], password)
        shot("se-10-approve")
        app.buttons["emergency.confirm"].tap()
        notice(contains: "can view your vaults now")

        // Bea opens Ada's personal vault with her own keys.
        let view = try await srv.call("GET", "/emergency-access/\(grantId)/vault", session: beaSession)
        let adaId = ((view["grant"] as! [String: Any])["grantor"] as! [String: Any])["id"] as! String
        let ek = try beaSession.account.openSealedEmergencyKey(grantorId: adaId, grantId: grantId, sealed: view["sealed_key"] as! String)
        let shared = (view["vaults"] as! [[String: Any]]).first!
        let vid = shared["id"] as! String
        let oldKey = try ek.openVaultKey(vaultId: vid, wrapped: shared["wrapped_key"] as! String)
        XCTAssertEqual(names(oldKey, view["items"] as! [[String: Any]], vault: vid), ["Passport"])
        let epochBefore = try await ownVault(srv, adaHelper).epoch

        // Ada removes Bea: the personal vault gets a new key at once.
        pullToRefresh()
        emergencyButton("Remove…").tap()
        shot("se-11-remove")
        app.buttons["emergency.confirm"].tap()
        notice(contains: "vault keys changed")
        let afterRemoval = try await ownVault(srv, adaHelper)
        XCTAssertGreaterThan(afterRemoval.epoch, epochBefore, "key replaced")
        XCTAssertEqual(names(oldKey, afterRemoval.items, vault: vid), [], "Bea's key opens nothing any more")
        XCTAssertEqual(names(afterRemoval.key, afterRemoval.items, vault: vid), ["Passport"])
        do {
            _ = try await srv.call("GET", "/emergency-access/\(grantId)/vault", session: beaSession)
            XCTFail("Bea still has access")
        } catch {}

        // MARK: Emergency access, Cy names Ada: accept, ask, view read-only.
        let cySession = try await srv.login(email: cy, password: password)
        try await srv.createItem(cySession, item("Bank PIN", password: "Cy-Bank-9876"))
        let invite = try await srv.call("POST", "/emergency-access", ["grantee_email": ada, "wait_days": 1], session: cySession)
        let cyGrant = invite["id"] as! String
        emergencyButton("Accept").tap()
        notice(contains: "confirms you next")
        // Cy confirms Ada (the core's emergency key, sealed to Ada, wrapping Cy's personal vault).
        let listed = try await srv.call("GET", "/emergency-access", session: cySession)
        let g = (listed["as_grantor"] as! [[String: Any]]).first { $0["id"] as? String == cyGrant }!
        let adaKey = (g["grantee"] as! [String: Any])["public_key"] as! String
        XCTAssertEqual(adaKey, adaHelper.account.publicKey())
        let cyId = try await userId(srv, cySession)
        let made = try cySession.account.newEmergencyKey(grantId: cyGrant)
        let cyVault = try await ownVault(srv, cySession)
        try await srv.call("POST", "/emergency-access/\(cyGrant)/confirm", [
            "sealed_key": try made.key.sealFor(contactPublicKey: adaKey, grantorId: cyId, grantId: cyGrant),
            "grantor_key": made.wrapped,
            "vault_keys": [["vault_id": cyVault.id, "wrapped_key": try made.key.wrapVaultKey(vaultKey: cyVault.key, vaultId: cyVault.id), "key_epoch": cyVault.epoch]],
        ], session: cySession)
        emergencyButton("Ask for access…").tap()
        app.buttons["emergency.confirm"].tap()
        notice(contains: "was told about your request")
        let token = try await srv.reauth(cySession)
        try await srv.call("POST", "/emergency-access/\(cyGrant)/approve", session: cySession, headers: ["x-reauth-token": token])
        emergencyButton("View Cy Grantor's vaults").tap()
        wait(app.navigationBars["Cy Grantor's vaults"])
        wait(app.staticTexts["Bank PIN"], 30).tap()
        wait(app.staticTexts["View only"].exists ? app.staticTexts["View only"] : app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'View only'")).firstMatch)
        shot("se-12-grantor-item")
        app.buttons["copy:Password"].firstMatch.tap()
        notice(contains: "Password copied")
    }
}
