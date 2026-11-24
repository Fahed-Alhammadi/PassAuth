import PassAuthCore
import XCTest

/// Signed sharing against the throwaway server (debug builds). The test acts as the other people
/// through the server's API with the Rust core (`TestServer`), and as the app's account from a
/// second device where the app has no sharing screens:
///
/// - Eli shares "Family" with the app's account, signed (share signature + roster v1): the app
///   shows "Signed by eli@…", accepts it, and lists the vault as signed.
/// - Eli shares "Planted" without a signature: the app offers Decline only.
/// - Eli shares "Elsewhere" without a signature and the account accepts it from another device: the
///   app holds it locked with "Ask the vault's owner to sign this vault.", without Accept or Decline
///   (an unsigned vault the server lists is never declinable: cross-client rule 1).
/// - The app's account shares its own vault with Gus (accepts) and Fay (declines, so the server
///   asks for a new key): the app replaces the key from Emergency access after confirming that Fay
///   is gone; Gus's device checks the new share, the new roster and the items.
@MainActor
final class SignedSharingUITests: UITestBase {
    private func scrollTo(_ e: XCUIElement, max: Int = 10) {
        var n = 0
        while (!e.exists || !e.isHittable) && n < max {
            app.swipeUp(velocity: .slow)
            n += 1
        }
    }

    private func goTo(_ name: String) {
        let t = app.tabBars.buttons[name].firstMatch
        if t.waitForExistence(timeout: 3) { t.tap() } else { wait(app.buttons[name].firstMatch).tap() }
    }

    private func settingsPage(_ id: String) {
        goTo("Settings")
        while !app.buttons["settings.\(id)"].exists && app.navigationBars.buttons.count > 0 && !app.navigationBars["Settings"].exists { back() }
        scrollTo(app.buttons["settings.\(id)"])
        wait(app.buttons["settings.\(id)"], 30).tap()
    }

    private func pullToRefresh() {
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
        start.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.85)))
        sleep(2)
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

    func testSignedSharing() async throws {
        continueAfterFailure = false
        let srv = TestServer(server)
        let stamp = Int(Date().timeIntervalSince1970)
        let dana = "dana\(stamp)@example.com", eli = "eli\(stamp)@example.com", gus = "gus\(stamp)@example.com", fay = "fay\(stamp)@example.com"
        for (email, name) in [(dana, "Dana"), (eli, "Eli Sharer"), (gus, "Gus"), (fay, "Fay")] {
            try await srv.register(email: email, password: password, name: name)
        }
        let eliS = try await srv.login(email: eli, password: password)
        let gusS = try await srv.login(email: gus, password: password)
        let fayS = try await srv.login(email: fay, password: password)
        let eliId = try await srv.makeIdentity(eliS)
        let gusId = try await srv.makeIdentity(gusS)
        let fayPub = try await srv.makeIdentity(fayS).publicIdentityJson()

        // The app signs in and makes the account's signing identity.
        app.launchArguments = ["-PAResetState"]
        app.launch()
        signIn(dana)
        var danaPub: String?
        for _ in 0..<30 {
            if let p = try await srv.lookupIdentity(dana, session: eliS), p.contains("\"signing_key\":\"") {
                danaPub = p
                break
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        XCTAssertNotNil(danaPub, "the app uploaded its signing identity")
        settingsPage("account")
        wait(app.staticTexts["Your identity fingerprint"])
        shot("signed-01-own-fingerprint")

        // Dana's own vault shared from another device: Gus accepts, Fay declines.
        let danaS = try await srv.login(email: dana, password: password)
        let danaId = try await srv.openIdentity(danaS)
        let own = try await srv.ownVault(danaS)
        try await srv.shareSigned(danaS, signing: danaId, vault: own.id, key: own.key, epoch: 0, to: gus, role: "write",
                                  current: [(try danaId.publicIdentityJson(), "owner")])
        try await srv.call("POST", "/vaults/\(own.id)/invitation/accept", session: gusS)
        try await srv.shareSigned(danaS, signing: danaId, vault: own.id, key: own.key, epoch: 0, to: fay, role: "read",
                                  current: [(try danaId.publicIdentityJson(), "owner"), (try gusId.publicIdentityJson(), "write")])
        try await srv.call("DELETE", "/vaults/\(own.id)/invitation", session: fayS)

        // Eli: "Family", signed; "Planted", not signed.
        let family = try await srv.newVault(eliS, name: "Family")
        try await srv.createItem(eliS, vault: family.id, key: family.key, name: "Family bank")
        try await srv.shareSigned(eliS, signing: eliId, vault: family.id, key: family.key, epoch: 0, to: dana, role: "write",
                                  current: [(try eliId.publicIdentityJson(), "owner")])
        let planted = try await srv.newVault(eliS, name: "Planted")
        try await srv.shareUnsigned(eliS, vault: planted.id, key: planted.key, to: dana, role: "read")
        let elsewhere = try await srv.newVault(eliS, name: "Elsewhere")
        try await srv.shareUnsigned(eliS, vault: elsewhere.id, key: elsewhere.key, to: dana, role: "read")
        try await srv.call("POST", "/vaults/\(elsewhere.id)/invitation/accept", session: danaS)

        // Invitations: the signed one names its signer; the unsigned one can only be declined.
        goTo("Vault")
        pullToRefresh()
        settingsPage("invitations")
        wait(app.staticTexts["Family"], 30)
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Signed by \(eli)")).firstMatch)
        shot("signed-02-invitation-signed")
        let unsigned = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "isn't signed")).firstMatch
        scrollTo(unsigned)
        wait(unsigned)
        XCTAssertTrue(app.buttons["invitation.decline.\(planted.id)"].exists)
        XCTAssertFalse(app.buttons["invitation.accept.\(planted.id)"].exists, "an unsigned invitation can't be accepted")
        shot("signed-02-invitation-unsigned")
        // The unsigned membership accepted elsewhere: held, neither accepted nor declined here.
        let held = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@", "Ask the vault's owner to sign this vault.")).firstMatch
        scrollTo(held)
        wait(held, 30)
        XCTAssertTrue(app.descendants(matching: .any)["invitation.consent.\(elsewhere.id)"].exists)
        XCTAssertFalse(app.buttons["invitation.decline.\(elsewhere.id)"].exists, "no Decline for an unsigned vault the server lists")
        XCTAssertFalse(app.buttons["invitation.accept.\(elsewhere.id)"].exists)
        shot("signed-02-consent-unsigned-held")
        // The list is in the server's order: scroll to Family's Accept.
        let acceptFamily = app.buttons["invitation.accept.\(family.id)"]
        if !acceptFamily.exists {
            app.swipeDown(velocity: .fast)
            app.swipeDown(velocity: .fast)
        }
        scrollTo(acceptFamily)
        wait(acceptFamily).tap()
        wait(app.buttons["invitation.confirm"]).tap()
        notice(contains: "You joined")

        // The vault is in use and labelled with its signer.
        settingsPage("sharedVaults")
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "Signed by \(eli)")).firstMatch, 30)
        shot("signed-03-shared-vaults")

        // Fay declined: the server asks for a new key of Dana's vault, replaced from Emergency access.
        goTo("Vault")
        pullToRefresh()
        settingsPage("emergency")
        let rotate = app.buttons["emergency.rotate"]
        for _ in 0..<5 where !rotate.exists {
            back()
            goTo("Vault")
            pullToRefresh()
            settingsPage("emergency")
        }
        scrollTo(rotate)
        wait(rotate, 30).tap()
        // Fay is named in the signed member list but gone: confirmed first.
        wait(app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "no longer a member")).firstMatch, 30)
        shot("signed-04-confirm-left")
        confirm("Replace the key")
        notice(contains: "Vault keys replaced")

        // Gus's device: the new key is sealed and signed for him by Dana at epoch 1, the roster
        // follows the one before and commits to the key, the items decrypt.
        let sync = try await srv.call("GET", "/sync", session: gusS)
        let row = try XCTUnwrap((sync["vaults"] as? [[String: Any]])?.first { $0["id"] as? String == own.id })
        XCTAssertEqual(row["key_epoch"] as? Int, 1)
        let share = try XCTUnwrap(row["share"] as? [String: Any])
        let signer = try srv.jsonText(share["signer"])
        _ = try verifyShare(vaultId: own.id, recipientJson: try gusId.publicIdentityJson(), role: "write", keyEpoch: 1,
                            sealedKey: row["wrapped_key"] as? String ?? "", signerJson: signer, signature: share["signature"] as? String ?? "")
        let rosters = try await srv.call("GET", "/vaults/\(own.id)/rosters?after=0", session: gusS)
        let chain = rosters["rosters"] as? [String] ?? []
        XCTAssertEqual(chain.count, 3)
        let latest = try verifyRosterChain(vaultId: own.id, trusted: nil, newer: chain, latest: try XCTUnwrap(chain.last))
        XCTAssertEqual(try rosterMemberRole(rosterJson: latest, identityJson: try gusId.publicIdentityJson()), "write")
        XCTAssertNil(try rosterMemberRole(rosterJson: latest, identityJson: fayPub), "Fay, who declined, isn't in the new roster")
        let key = try gusS.account.openVaultKey(vaultId: own.id, wrapped: row["wrapped_key"] as? String ?? "", kind: "sealed", keyEpoch: 1, legacyAllowed: false)
        XCTAssertTrue(try key.matchesRoster(vaultId: own.id, rosterJson: latest))
        _ = danaPub
    }
}

// MARK: Signed sharing as another device

extension TestServer {
    func jsonText(_ v: Any?) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: v ?? NSNull(), options: [.fragmentsAllowed]), as: UTF8.self)
    }

    /// Make and upload the account's signing identity.
    func makeIdentity(_ s: Session) async throws -> SigningIdentity {
        let made = try s.account.newSigningIdentity()
        try await call("PUT", "/account/identity", try JSONSerialization.jsonObject(with: Data(made.recordJson.utf8)) as? [String: Any], session: s)
        return made.identity
    }

    /// The account's signing identity as the server lists it, opened with its key.
    func openIdentity(_ s: Session) async throws -> SigningIdentity {
        let sync = try await call("GET", "/sync", session: s)
        let record = (sync["user"] as? [String: Any])?["identity"]
        return try s.account.openSigningIdentity(recordJson: try jsonText(record))
    }

    /// `{user_id, public_key, signing_key, identity_signature}` from `/users/lookup`.
    func lookupIdentity(_ email: String, session s: Session) async throws -> String? {
        let r = try await call("GET", "/users/lookup?email=\(email.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? email)", session: s)
        guard let id = r["user_id"] as? String else { return nil }
        let o: [String: Any] = ["user_id": id, "public_key": r["public_key"] ?? NSNull(), "signing_key": r["signing_key"] ?? NSNull(),
                                "identity_signature": r["identity_signature"] ?? NSNull(), "x25519_signature": r["x25519_signature"] ?? NSNull()]
        return try jsonText(o)
    }

    func ownVault(_ s: Session) async throws -> (id: String, key: VaultKey) {
        let sync = try await call("GET", "/sync", session: s)
        guard let v = (sync["vaults"] as? [[String: Any]])?.first(where: { $0["role"] as? String == "owner" }) else { throw Failure(description: "no vault") }
        let id = v["id"] as! String
        return (id, try s.account.openVaultKey(vaultId: id, wrapped: v["wrapped_key"] as! String, kind: v["key_kind"] as! String,
                                         keyEpoch: UInt64(v["key_epoch"] as? Int ?? 0), legacyAllowed: true))
    }

    func newVault(_ s: Session, name: String) async throws -> (id: String, key: VaultKey) {
        let id = try newId()
        let nv = try s.account.newVaultKey(vaultId: id)
        try await call("POST", "/vaults", ["id": id, "meta": try nv.key.encryptMeta(vaultId: id, metaJson: "{\"name\":\"\(name)\"}"), "wrapped_key": nv.wrapped], session: s)
        return (id, nv.key)
    }

    func createItem(_ s: Session, vault: String, key: VaultKey, name: String) async throws {
        let item: [String: Any] = ["name": name, "notes": "", "favorite": false, "fields": [], "created_at": 1_700_000_000, "updated_at": 1_700_000_000,
                                   "login": ["username": "eli", "password": "pw", "urls": [["url": "https://familybank.test"]]]]
        let enc = try key.encryptItem(itemJson: try jsonText(item), id: try newId(), vaultId: vault)
        try await call("POST", "/items", ["id": enc.id, "vault_id": enc.vaultId, "key": enc.key, "data": enc.data, "key_epoch": 0], session: s)
    }

    private func member(_ identity: String, _ role: String) throws -> [String: Any] {
        var o = try JSONSerialization.jsonObject(with: Data(identity.utf8)) as? [String: Any] ?? [:]
        o["role"] = role
        return o
    }

    /// Share `vault` with `email`, sealed and signed by `signing`, with the next roster after the
    /// vault's latest one (`current` members plus the new one), reviewed as an app would.
    func shareSigned(_ s: Session, signing: SigningIdentity, vault: String, key: VaultKey, epoch: UInt64, to email: String, role: String,
                     current: [(String, String)]) async throws {
        guard let to = try await lookupIdentity(email, session: s) else { throw Failure(description: "no \(email)") }
        let userId = (try JSONSerialization.jsonObject(with: Data(to.utf8)) as? [String: Any])?["user_id"] as? String ?? ""
        let share = try signing.sealAndSignShare(vaultKey: key, vaultId: vault, recipientJson: to, role: role, keyEpoch: epoch)
        let members = try jsonText(try current.map { try member($0.0, $0.1) } + [try member(to, role)])
        let listed = try await call("GET", "/vaults/\(vault)/members", session: s)
        let previous = listed["member_roster"] as? String
        let review = try rosterReview(vaultId: vault, previous: previous, signerJson: try signing.publicIdentityJson(), membersJson: members, pinsJson: nil)
        let digest = (try JSONSerialization.jsonObject(with: Data(review.utf8)) as? [String: Any])?["digest"] as? String ?? ""
        let roster = try signing.signRoster(vaultKey: key, vaultId: vault, previous: previous, keyEpoch: epoch, membersJson: members, reviewed: digest)
        try await call("POST", "/vaults/\(vault)/members", ["user_id": userId, "role": role, "sealed_key": share.sealedKey, "key_epoch": epoch,
                                                           "signature": share.signature, "roster": roster], session: s)
    }

    /// Share `vault` with `email` without a signature (as apps from before do).
    func shareUnsigned(_ s: Session, vault: String, key: VaultKey, to email: String, role: String) async throws {
        let r = try await call("GET", "/users/lookup?email=\(email.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? email)", session: s)
        let sealed = try key.shareTo(vaultId: vault, recipientPublicKey: r["public_key"] as? String ?? "")
        try await call("POST", "/vaults/\(vault)/members", ["user_id": r["user_id"] ?? "", "role": role, "sealed_key": sealed, "key_epoch": 0], session: s)
    }
}
