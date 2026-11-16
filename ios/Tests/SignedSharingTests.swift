import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// Signed sharing, the checks this device runs (`Shared/SignedSharing.swift`), with real keys
/// from the core: a vault row's roster chain, key epoch and commitment, its share signature and
/// signer against the key pins, and the account's admission verdict (consent, grandfathering,
/// tombstones, paused); invitations; the device memory and its merge; the review reader; the
/// wording. Shared by the iOS tests and the macOS AutoFill tests.
final class SignedSharingTests: XCTestCase {
    /// Alice owns a vault and shares it with Bob (signed, with roster version 1).
    struct World {
        let alice: Account
        let aliceSigning: SigningIdentity
        let bob: Account
        let bobSigning: SigningIdentity
        let aliceId: String
        let bobId: String
        let vaultId: String
        let key: VaultKey
        let wrappedForAlice: String
        let share: SignedShare
        let roster: String
        var alicePub: String { (try? aliceSigning.publicIdentityJson()) ?? "" }
        var bobPub: String { (try? bobSigning.publicIdentityJson()) ?? "" }
        var bobSelf: SharingSelf { SharingSelf(identity: bobPub, userId: bobId, signingHash: bobSigning.identityHash(), paused: false) }
        var aliceSelf: SharingSelf { SharingSelf(identity: alicePub, userId: aliceId, signingHash: aliceSigning.identityHash(), paused: false) }
    }

    static func member(_ identity: String, _ role: String) -> JSON {
        SharingIdentity.memberJson(identity, role: role) ?? .null
    }

    /// A roster signed the way the apps do: reviewed, then signed over the reviewed list.
    static func signRoster(_ signer: SigningIdentity, key: VaultKey, vault: String, previous: String?, epoch: UInt64, members: [JSON]) throws -> String {
        let list = JSON.array(members).text
        let review = try XCTUnwrap(MemberReview.read(try rosterReview(vaultId: vault, previous: previous, signerJson: try signer.publicIdentityJson(),
                                                                      membersJson: list, pinsJson: nil)))
        return try signer.signRoster(vaultKey: key, vaultId: vault, previous: previous, keyEpoch: epoch, membersJson: list, reviewed: review.digest)
    }

    static func world(epoch: UInt64 = 0, bobRole: String = "write") throws -> World {
        let aliceId = try newId(), bobId = try newId()
        let alice = try createAccount(accountId: aliceId, password: "correct horse battery", withSecretKey: false).account
        let bob = try createAccount(accountId: bobId, password: "correct horse battery", withSecretKey: false).account
        let aliceSigning = try alice.newSigningIdentity().identity
        let bobSigning = try bob.newSigningIdentity().identity
        let vaultId = try newId()
        let made = try alice.newVaultKey(vaultId: vaultId)
        let bobPub = try bobSigning.publicIdentityJson()
        let share = try aliceSigning.sealAndSignShare(vaultKey: made.key, vaultId: vaultId, recipientJson: bobPub, role: "write", keyEpoch: epoch)
        let roster = try signRoster(aliceSigning, key: made.key, vault: vaultId, previous: nil, epoch: epoch,
                                    members: [member(try aliceSigning.publicIdentityJson(), "owner"), member(bobPub, bobRole)])
        return World(alice: alice, aliceSigning: aliceSigning, bob: bob, bobSigning: bobSigning, aliceId: aliceId, bobId: bobId, vaultId: vaultId,
                     key: made.key, wrappedForAlice: made.wrapped, share: share, roster: roster)
    }

    /// The `share` of a `/sync` row signed by `signing`.
    static func shareJSON(_ signature: String, _ signer: SigningIdentity, email: String = "alice@example.com", deleted: Bool = false) throws -> JSON {
        guard case .object(var s) = try JSON.parse(try signer.publicIdentityJson()) else { return .null }
        s["email"] = .string(email)
        s["name"] = "Alice"
        return ["signature": .string(signature), "signer": .object(s), "signer_deleted": .bool(deleted)]
    }

    private func world(epoch: UInt64 = 0, bobRole: String = "write") throws -> World { try Self.world(epoch: epoch, bobRole: bobRole) }
    private func shareJSON(_ signature: String, _ signer: SigningIdentity, email: String = "alice@example.com") throws -> JSON {
        try Self.shareJSON(signature, signer, email: email)
    }

    /// Bob's row for the shared vault.
    private func bobRow(_ w: World, role: String = "write", epoch: Int64 = 0, share: JSON? = nil, roster: String?? = nil,
                        wrapped: String? = nil) throws -> SyncVault {
        SyncVault(id: w.vaultId, meta: "", role: role, wrappedKey: wrapped ?? w.share.sealedKey, keyKind: "sealed", keyEpoch: epoch, seq: 1,
                  share: try share ?? shareJSON(w.share.signature, w.aliceSigning), memberRoster: roster ?? w.roster, memberRosterSeq: 1)
    }

    /// The pins of a Bob who accepted the vault (its epoch pinned with roster 1, Alice pinned).
    private func accepted(_ w: World, verified: Bool = false) throws -> String {
        var p = try pinSet(pinsJson: nil, identityJson: w.alicePub, email: "alice@example.com", verified: verified, now: 1)
        p = try pinsSetEpoch(pinsJson: p, vaultId: w.vaultId, currentJson: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0), rosterVersion: 1)
        return p
    }

    private func check(_ w: World, _ row: SyncVault, pins: String?, me: SharingSelf? = nil, remembered: String? = nil, newer: [String]? = nil,
                       seenSigned: Bool = false, tooLarge: Bool = false) throws -> SignedSharing.VaultCheck {
        let key = try w.bob.openVaultKey(vaultId: row.id, wrapped: row.wrappedKey, kind: row.keyKind, keyEpoch: UInt64(row.keyEpoch ?? 0), legacyAllowed: true)
        return SignedSharing.checkVault(row, key: key, me: me ?? w.bobSelf, pins: pins, remembered: remembered, newer: newer, tooLarge: tooLarge,
                                        seenSigned: seenSigned, now: 1000)
    }

    private func okPins(_ c: SignedSharing.VaultCheck) -> String? {
        if case .ok(_, _, let p) = c { return p }
        return nil
    }

    // MARK: Vault rows

    func testANeverAcceptedSealedVaultAsksForConsentAndAcceptingMakesItUsable() throws {
        let w = try world()
        // Review H2: a signed share Bob's account never accepted (a planted one looks the same).
        let first = try check(w, try bobRow(w), pins: nil, newer: [w.roster])
        guard case .consent(let a, let rejoin, _, let own, let signer) = first else { return XCTFail("\(first)") }
        XCTAssertFalse(rejoin)
        XCTAssertFalse(own)
        XCTAssertEqual(signer?.pin, .new)
        XCTAssertEqual(a.roster, w.roster)
        XCTAssertEqual(a.rosterVersion, 1)
        XCTAssertEqual(a.signer?.userId, w.aliceId)
        // The chain fetched for it is part of what accepting records (`chain_hashes`).
        XCTAssertEqual(a.chainHashes, ["1": try rosterHash(rosterJson: w.roster)])
        XCTAssertTrue(a.signedShare)
        // Accepting = the signer pinned, then `pins_accept` with the observation admitted.
        var pins = try pinSet(pinsJson: nil, identityJson: try XCTUnwrap(a.signer).identity, email: "alice@example.com", verified: false, now: 1)
        pins = try pinsAccept(pinsJson: pins, observationJson: a.observation(vaultId: w.vaultId, paused: false))
        let accepted = try JSON.parse(pins)
        XCTAssertEqual(accepted["epochs"]?[w.vaultId]?["roster_hash"]?.string, try rosterHash(rosterJson: w.roster))
        XCTAssertEqual(accepted["epochs"]?[w.vaultId]?["signed_since"]?.number, 1)
        let after = try check(w, try bobRow(w), pins: pins, remembered: w.roster)
        guard case .ok(.signed(let s), let roster, let p) = after else { return XCTFail("\(after)") }
        XCTAssertEqual(s.pin, .unverified)
        XCTAssertEqual(s.pinnedEmail, "alice@example.com")
        XCTAssertEqual(roster, w.roster)
        // The roster's version and hash are recorded once; nothing new to pin after that.
        guard case .ok(_, _, let again) = try check(w, try bobRow(w), pins: p, remembered: w.roster) else { return XCTFail() }
        XCTAssertEqual(again, p)
    }

    func testAnAcceptedSignedShareIsUsedAndItsNewSignerPinnedOnlyOnceItPassed() throws {
        let w = try world()
        // The epoch accepted (an earlier app), Alice not pinned yet.
        let pins = try pinsSetEpoch(pinsJson: nil, vaultId: w.vaultId, currentJson: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0),
                                    rosterVersion: nil)
        let result = try check(w, try bobRow(w), pins: pins, newer: [w.roster])
        guard case .ok(.signed(let signer), let roster, let after) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(roster, w.roster)
        XCTAssertEqual(signer.pin, .new)
        XCTAssertEqual(signer.email, "alice@example.com")
        XCTAssertEqual(signer.fingerprint, w.aliceSigning.fingerprint())
        XCTAssertEqual(SharingText.signedBy(signer), "Signed by alice@example.com")
        XCTAssertEqual(try pinCheck(pinsJson: after, identityJson: w.alicePub, email: nil), "match")
        XCTAssertTrue(KeyPinsReader.signedSince(after, w.vaultId), "the first trusted roster marks the vault signed for the account")
        // A row that fails a later check pins nothing (pins come back only with `.ok`).
        XCTAssertEqual(try check(w, try bobRow(w, role: "admin"), pins: pins, newer: [w.roster]), .refused(.unverified))
    }

    func testForgedOrChangedSharesAreRefused() throws {
        let w = try world()
        let pins = try accepted(w)
        // The server says Bob may administer; the signature says "write".
        XCTAssertEqual(try check(w, try bobRow(w, role: "admin"), pins: pins, newer: [w.roster]), .refused(.unverified))
        // A signature by Bob over his own share: he isn't an owner or admin of the roster.
        let selfSigned = try w.bobSigning.signShare(vaultId: w.vaultId, recipientJson: w.bobPub, role: "write", keyEpoch: 0, sealedKey: w.share.sealedKey)
        XCTAssertEqual(try check(w, try bobRow(w, share: try shareJSON(selfSigned, w.aliceSigning)), pins: pins, newer: [w.roster]), .refused(.unverified))
        // Another epoch than the signed one.
        XCTAssertEqual(try check(w, try bobRow(w, epoch: 1), pins: pins, newer: [w.roster]), .refused(.unverified))
        // A newer roster is needed but couldn't be fetched (offline), or there were too many.
        XCTAssertEqual(try check(w, try bobRow(w), pins: pins, newer: nil), .refused(.offline))
        XCTAssertEqual(try check(w, try bobRow(w), pins: pins, newer: nil, tooLarge: true), .refused(.tooLarge))
        // A roster for another key (the server's own key under the same vault id).
        let other = try w.alice.newVaultKey(vaultId: w.vaultId)
        let rogue = try Self.signRoster(w.aliceSigning, key: other.key, vault: w.vaultId, previous: nil, epoch: 0,
                                        members: [Self.member(w.alicePub, "owner"), Self.member(w.bobPub, "write")])
        XCTAssertEqual(try check(w, try bobRow(w, roster: .some(rogue)), pins: pins, newer: [rogue]), .refused(.unverified))
        // The server serves no roster any more after this device trusted one: a rollback.
        XCTAssertEqual(try check(w, try bobRow(w, roster: .some(nil)), pins: pins, remembered: w.roster), .refused(.unverified))
        // A signed share whose roster was stripped (never trusted on this device): downgraded.
        XCTAssertEqual(try check(w, try bobRow(w, roster: .some(nil)), pins: pins), .refused(.admission("downgraded")))
        // A share that is an object but no share at all.
        XCTAssertEqual(try check(w, try bobRow(w, share: ["signature": 3]), pins: pins, newer: [w.roster]), .refused(.unverified))
        // No key epoch.
        var noEpoch = try bobRow(w)
        noEpoch.keyEpoch = nil
        XCTAssertEqual(try check(w, noEpoch, pins: pins, newer: [w.roster]), .refused(.admission("missing_epoch")))
    }

    func testARosterOfAnotherVaultIsRefused() throws {
        // Review L1: the same people, the same key, another vault id.
        let w = try world()
        let otherVault = try newId()
        let foreign = try Self.signRoster(w.aliceSigning, key: w.key, vault: otherVault, previous: nil, epoch: 0,
                                          members: [Self.member(w.alicePub, "owner"), Self.member(w.bobPub, "write")])
        XCTAssertEqual(try check(w, try bobRow(w, roster: .some(foreign)), pins: try accepted(w), newer: [foreign]), .refused(.unverified))
        XCTAssertNil(SignedSharing.head(w.vaultId, remembered: nil, latest: foreign))
    }

    func testTheRosterMustGiveThisAccountTheRowsRole() throws {
        // Review L5: Alice's share says "write", her roster lists Bob as a reader.
        let w = try world(bobRole: "read")
        XCTAssertEqual(try check(w, try bobRow(w), pins: try accepted(w), newer: [w.roster]), .refused(.unverified))
    }

    func testEpochPinsRefuseAnOlderOrRelabelledKey() throws {
        let w = try world()
        // The account accepted epoch 3 of another key: epoch 0 now is older.
        let later = try w.alice.newVaultKey(vaultId: w.vaultId).key
        var pins = try pinsSetEpoch(pinsJson: nil, vaultId: w.vaultId, currentJson: try later.epochPinJson(vaultId: w.vaultId, keyEpoch: 3), rosterVersion: nil)
        XCTAssertEqual(try check(w, try bobRow(w), pins: pins, newer: [w.roster]), .refused(.admission("older")))
        // The same epoch under another key: a conflict.
        let other = try w.alice.newVaultKey(vaultId: w.vaultId).key
        pins = try pinsSetEpoch(pinsJson: nil, vaultId: w.vaultId, currentJson: try other.epochPinJson(vaultId: w.vaultId, keyEpoch: 0), rosterVersion: nil)
        XCTAssertEqual(try check(w, try bobRow(w), pins: pins, newer: [w.roster]), .refused(.admission("conflict")))
    }

    func testAChangedSignerStopsAndCanBeTrustedDeliberately() throws {
        let w = try world()
        // Another identity pinned for Alice's user id (an account with the same id and other keys).
        let impostor = try createAccount(accountId: w.aliceId, password: "correct horse battery", withSecretKey: false).account
        let impostorSigning = try impostor.newSigningIdentity().identity
        var pins: String? = try pinSet(pinsJson: try accepted(w), identityJson: try impostorSigning.publicIdentityJson(), email: "alice@example.com",
                                       verified: true, now: 1)
        let result = try check(w, try bobRow(w), pins: pins, newer: [w.roster])
        guard case .refused(.keyChanged(let s)) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(s.pin, .changed)
        XCTAssertEqual(SharingText.keyChanged(s), "alice@example.com's keys changed. Compare their fingerprint with them before you continue.")
        // "Trust the new key" pins Alice's real identity; then the vault is used.
        pins = try pinSet(pinsJson: pins, identityJson: s.identity, email: s.listedEmail, verified: true, now: 2)
        guard case .ok(.signed(let after), _, _) = try check(w, try bobRow(w), pins: pins, newer: [w.roster]) else { return XCTFail() }
        XCTAssertEqual(after.pin, .verified)
    }

    func testAKnownEmailUnderANewAccountStops() throws {
        // Review H2: the server makes an account with a colleague's email; Bob pinned the real one.
        let w = try world()
        let colleague = try createAccount(accountId: try newId(), password: "correct horse battery", withSecretKey: false).account
        var pins = try pinSet(pinsJson: nil, identityJson: try colleague.newSigningIdentity().identity.publicIdentityJson(),
                              email: "alice@example.com", verified: true, now: 1)
        pins = try pinsSetEpoch(pinsJson: pins, vaultId: w.vaultId, currentJson: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0), rosterVersion: nil)
        let result = try check(w, try bobRow(w, share: try shareJSON(w.share.signature, w.aliceSigning, email: " Alice@Example.com ")), pins: pins,
                               newer: [w.roster])
        guard case .refused(.keyChanged(let s)) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(s.pin, .emailConflict)
        // Shown in the form pins compare.
        XCTAssertEqual(SharingText.keyChanged(s), SharingText.emailConflict("alice@example.com"))
    }

    func testSharesFromBeforeAreGrandfatheredOrNeedConsent() throws {
        let w = try world()
        let plain = try w.key.shareTo(vaultId: w.vaultId, recipientPublicKey: w.bob.publicKey())
        let old = SyncVault(id: w.vaultId, role: "write", wrappedKey: plain, keyKind: "sealed", keyEpoch: 0, share: nil, memberRoster: nil, memberRosterSeq: 0)
        // Present at the first signed sync: usable as "Not yet signed".
        let grandfathered = try pinsGrandfather(pinsJson: nil, vaultIds: [w.vaultId], createdIdentity: true)
        guard case .ok(.notYetSigned, nil, let p) = try check(w, old, pins: grandfathered) else { return XCTFail() }
        XCTAssertNotNil(p)
        // Not grandfathered: a consent that can't be accepted (no signer).
        guard case .consent(_, false, false, false, nil) = try check(w, old, pins: try pinsGrandfather(pinsJson: nil, vaultIds: [], createdIdentity: true)) else { return XCTFail() }
        // Seen signed before (on this device, or by the account) and now not: refused.
        XCTAssertEqual(try check(w, old, pins: grandfathered, seenSigned: true), .refused(.admission("downgraded")))
        XCTAssertEqual(try check(w, old, pins: try accepted(w)), .refused(.admission("downgraded")))
    }

    func testPausedRefusesEverySealedRowButNotTheAccountsOwn() throws {
        let w = try world()
        let paused = SharingSelf(identity: try w.bob.legacyIdentityJson(), userId: w.bobId, signingHash: nil, paused: true)
        XCTAssertEqual(try check(w, try bobRow(w), pins: try accepted(w), me: paused, newer: [w.roster]), .refused(.paused))
        let own = SyncVault(id: w.vaultId, role: "owner", wrappedKey: w.wrappedForAlice, keyKind: "account", keyEpoch: 0, memberRoster: w.roster, memberRosterSeq: 1)
        let key = try w.alice.openVaultKey(vaultId: w.vaultId, wrapped: w.wrappedForAlice, kind: "account", keyEpoch: 0, legacyAllowed: true)
        let alicePaused = SharingSelf(identity: try w.alice.legacyIdentityJson(), userId: w.aliceId, signingHash: nil, paused: true)
        guard case .ok(.own, _, _) = SignedSharing.checkVault(own, key: key, me: alicePaused, pins: nil, remembered: w.roster, newer: nil,
                                                             tooLarge: false, seenSigned: false, now: 1) else { return XCTFail() }
    }

    func testALeftVaultStaysRefused() throws {
        // Review L3: a tombstone instead of forgetting.
        let w = try world()
        let left = try pinsLeave(pinsJson: try accepted(w), vaultId: w.vaultId, rosterVersion: 1, now: 5)
        XCTAssertEqual(try check(w, try bobRow(w), pins: left, newer: [w.roster]), .refused(.admission("left")))
    }

    func testTheOwnersOwnVaultChecksItsRosterAndEpoch() throws {
        let w = try world()
        let row = SyncVault(id: w.vaultId, role: "owner", wrappedKey: w.wrappedForAlice, keyKind: "account", keyEpoch: 0, memberRoster: w.roster, memberRosterSeq: 1)
        let key = try w.alice.openVaultKey(vaultId: w.vaultId, wrapped: w.wrappedForAlice, kind: "account", keyEpoch: 0, legacyAllowed: true)
        let ok = SignedSharing.checkVault(row, key: key, me: w.aliceSelf, pins: nil, remembered: nil, newer: [w.roster], tooLarge: false, seenSigned: false, now: 1)
        guard case .ok(.own, let roster, let pins) = ok else { return XCTFail("\(ok)") }
        XCTAssertEqual(roster, w.roster)
        XCTAssertTrue(KeyPinsReader.signedSince(pins, w.vaultId))
        // A key that isn't the roster's.
        let other = try w.alice.newVaultKey(vaultId: w.vaultId)
        let bad = SignedSharing.checkVault(SyncVault(id: w.vaultId, role: "owner", wrappedKey: other.wrapped, keyKind: "account", keyEpoch: 0,
                                                     memberRoster: w.roster, memberRosterSeq: 1),
                                           key: other.key, me: w.aliceSelf, pins: nil, remembered: w.roster, newer: nil, tooLarge: false, seenSigned: false, now: 1)
        XCTAssertEqual(bad, .refused(.unverified))
        // A role the roster doesn't give.
        let notOwner = SignedSharing.checkVault(SyncVault(id: w.vaultId, role: "admin", wrappedKey: w.wrappedForAlice, keyKind: "account", keyEpoch: 0,
                                                          memberRoster: w.roster, memberRosterSeq: 1),
                                                key: key, me: w.aliceSelf, pins: nil, remembered: w.roster, newer: nil, tooLarge: false, seenSigned: false, now: 1)
        XCTAssertEqual(notOwner, .refused(.unverified))
        // A vault without a roster: only its epoch pin; signed before → refused without one.
        let plainRow = SyncVault(id: w.vaultId, role: "owner", wrappedKey: w.wrappedForAlice, keyKind: "account", keyEpoch: 0)
        guard case .ok(.own, nil, let p3) = SignedSharing.checkVault(plainRow, key: key, me: w.aliceSelf, pins: nil, remembered: nil, newer: nil,
                                                                    tooLarge: false, seenSigned: false, now: 1) else { return XCTFail() }
        XCTAssertNotNil(p3)
        XCTAssertEqual(SignedSharing.checkVault(plainRow, key: key, me: w.aliceSelf, pins: pins, remembered: nil, newer: nil, tooLarge: false,
                                                seenSigned: false, now: 1), .refused(.admission("downgraded")))
    }

    // MARK: Invitations

    private func invitation(_ w: World, role: String = "write", share: JSON?? = nil, roster: String? = nil) throws -> SyncInvitation {
        SyncInvitation(vaultId: w.vaultId, role: role, wrappedKey: w.share.sealedKey, meta: "m", keyEpoch: 0,
                       share: try share ?? shareJSON(w.share.signature, w.aliceSigning), memberRoster: roster ?? w.roster, memberRosterSeq: 1)
    }

    private func checkInvitation(_ w: World, _ inv: SyncInvitation, pins: String? = nil, me: SharingSelf? = nil, remembered: String? = nil,
                                 newer: [String]?) throws -> (InvitationTrust, Acceptance?) {
        let key = try? w.bob.openVaultKey(vaultId: inv.vaultId, wrapped: inv.wrappedKey, kind: "sealed", keyEpoch: 0, legacyAllowed: false)
        return SignedSharing.checkInvitation(inv, key: key, me: me ?? w.bobSelf, pins: pins, remembered: remembered, newer: newer, tooLarge: false)
    }

    func testInvitationsAreAcceptedOnlyWhenSigned() throws {
        let w = try world()
        let (trust, acceptance) = try checkInvitation(w, try invitation(w), newer: [w.roster])
        guard case .signed(let s) = trust else { return XCTFail("\(trust)") }
        XCTAssertTrue(trust.canAccept)
        XCTAssertEqual(acceptance?.roster, w.roster)
        XCTAssertEqual(acceptance?.rosterVersion, 1)
        XCTAssertEqual(acceptance?.signer?.userId, w.aliceId, "pinned only when accepted")
        XCTAssertEqual(s.pin, .new)
        // Not signed: Decline only.
        XCTAssertEqual(try checkInvitation(w, try invitation(w, share: .some(nil)), newer: [w.roster]).0, .unsigned)
        XCTAssertFalse(InvitationTrust.unsigned.canAccept)
        // No chain fetched, a role the roster doesn't give, a forged signature: refused.
        XCTAssertEqual(try checkInvitation(w, try invitation(w), newer: nil).0, .refused)
        XCTAssertEqual(try checkInvitation(w, try invitation(w, role: "admin"), newer: [w.roster]).0, .refused)
        let forged = try w.bobSigning.signShare(vaultId: w.vaultId, recipientJson: w.bobPub, role: "write", keyEpoch: 0, sealedKey: w.share.sealedKey)
        XCTAssertEqual(try checkInvitation(w, try invitation(w, share: .some(try shareJSON(forged, w.bobSigning))), newer: [w.roster]).0, .refused)
        // The server's own key sealed to Bob with Alice's real signature over another sealed key.
        let planted = try w.alice.newVaultKey(vaultId: w.vaultId).key.shareTo(vaultId: w.vaultId, recipientPublicKey: w.bob.publicKey())
        var inv = try invitation(w)
        inv.wrappedKey = planted
        XCTAssertEqual(try checkInvitation(w, inv, newer: [w.roster]).0, .refused)
        // Alice's keys changed since Bob pinned her.
        let impostor = try createAccount(accountId: w.aliceId, password: "correct horse battery", withSecretKey: false).account
        let pins = try pinSet(pinsJson: nil, identityJson: try impostor.newSigningIdentity().identity.publicIdentityJson(), email: "alice@example.com",
                              verified: false, now: 1)
        guard case .keyChanged = try checkInvitation(w, try invitation(w), pins: pins, newer: [w.roster]).0 else { return XCTFail() }
        // Sharing paused on this device: nothing can be accepted.
        let paused = SharingSelf(identity: try w.bob.legacyIdentityJson(), userId: w.bobId, signingHash: nil, paused: true)
        XCTAssertEqual(try checkInvitation(w, try invitation(w), me: paused, newer: [w.roster]).0, .refused)
    }

    func testAVaultLeftComesBackOnlyWithANewerRoster() throws {
        let w = try world()
        let left = try pinsLeave(pinsJson: nil, vaultId: w.vaultId, rosterVersion: 1, now: 5)
        // The same roster again (the server replaying the old invitation): refused.
        XCTAssertEqual(try checkInvitation(w, try invitation(w), pins: left, newer: [w.roster]).0, .refused)
        // Re-shared with a newer roster (version 2): it can be accepted again.
        let v2 = try Self.signRoster(w.aliceSigning, key: w.key, vault: w.vaultId, previous: w.roster, epoch: 0,
                                     members: [Self.member(w.alicePub, "owner"), Self.member(w.bobPub, "write")].reversed())
        let again = try checkInvitation(w, try invitation(w, roster: v2), pins: left, remembered: w.roster, newer: [v2])
        guard case .signed = again.0 else { return XCTFail("\(again.0)") }
        XCTAssertEqual(again.1?.rosterVersion, 2)
    }

    func testInvitationsAreReadWithTheirSignedFields() throws {
        let raw = try JSON.parse(#"[{"vault_id":"v1","role":"read","wrapped_key":"wk","meta":"m","key_epoch":4,"member_roster":"{}","member_roster_seq":2,"share":{"signature":"s","signer":{"user_id":"u","public_key":"pk"}}},{"vault_id":"v2","role":"read","wrapped_key":"wk","meta":"m","share":null}]"#)
        let list = SyncInvitation.read(raw)
        XCTAssertEqual(list.count, 2)
        XCTAssertEqual(list[0].keyEpoch, 4)
        XCTAssertEqual(list[0].memberRoster, "{}")
        XCTAssertEqual(list[0].memberRosterSeq, 2)
        XCTAssertEqual(ShareRecord.read(list[0].share)?.signerId, "u")
        XCTAssertNil(list[1].share)
        XCTAssertNil(ShareRecord.read(list[1].share))
    }

    func testAConsentWithoutASignedShareCantBeAccepted() {
        var inv = Invitation(vaultId: "v", role: "read", name: "Planted", trust: .unsigned)
        inv.consent = .added
        XCTAssertFalse(inv.canAccept)
        var signed = Invitation(vaultId: "v", role: "read", name: "Family",
                                trust: .signed(SignerInfo(userId: "u", email: "a@x", name: "", fingerprint: "F", deleted: false, pin: .new, identity: "")))
        signed.consent = .added
        XCTAssertFalse(signed.canAccept, "nothing to write on accepting")
        signed.acceptance = Acceptance(epochPin: "{}", rosterVersion: 1, roster: "r", signer: nil)
        XCTAssertTrue(signed.canAccept)
        XCTAssertEqual(SharingText.consent("Family"), "Your server added \u{201C}Family\u{201D} to your account. Accept only if you expected it.")
    }

    // MARK: Memory, pins, wording, rows

    func testSyncRowsKeepTheirSignedFieldsInTheCopy() throws {
        let json = #"{"revision":1,"vaults":[{"id":"v","meta":"m","role":"read","wrapped_key":"w","key_kind":"sealed","key_epoch":2,"seq":1,"member_roster":"R","member_roster_seq":3,"share":{"signature":"s","signer":{"user_id":"u","public_key":"pk","email":"a@b.c"},"signer_deleted":true}}],"items":[]}"#
        let snap = try XCTUnwrap(SyncSnapshot.decode(Data(json.utf8)))
        let again = try XCTUnwrap(SyncSnapshot.decode(try snap.encoded()))
        XCTAssertEqual(again.vaults.first?.memberRoster, "R")
        XCTAssertEqual(again.vaults.first?.memberRosterSeq, 3)
        let share = try XCTUnwrap(ShareRecord.read(again.vaults.first?.share))
        XCTAssertTrue(share.signerDeleted)
        XCTAssertEqual(share.email, "a@b.c")
        let info = SignerInfo(userId: "u", email: "a@b.c", name: "", fingerprint: "F", deleted: true, pin: .unverified, identity: "")
        XCTAssertEqual(SharingText.signedBy(info), "Signed by a@b.c (account deleted)")
    }

    func testThePinnedEmailIsShownFirst() {
        // Review M2: "Verified" sits next to the pinned email, the server's new one is only listed.
        let s = SignerInfo(userId: "u", email: "alice@evil.example", name: "Alice", fingerprint: "F", deleted: false, pin: .verified, identity: "",
                           pinnedEmail: "alice@example.com")
        XCTAssertEqual(s.email, "alice@example.com")
        XCTAssertEqual(SharingText.signedBy(s), "Signed by alice@example.com")
        XCTAssertEqual(s.otherListedEmail, "alice@evil.example")
        XCTAssertEqual(SharingText.listedAs(s.otherListedEmail ?? ""), "Listed by your server as alice@evil.example")
        let same = SignerInfo(userId: "u", email: "Alice@Example.com", name: "", fingerprint: "F", deleted: false, pin: .verified, identity: "",
                              pinnedEmail: "alice@example.com")
        XCTAssertNil(same.otherListedEmail)
        // Not pinned yet: the listed email.
        let fresh = SignerInfo(userId: "u", email: "bob@example.com", name: "Bob", fingerprint: "F", deleted: false, pin: .new, identity: "")
        XCTAssertEqual(fresh.email, "bob@example.com")
    }

    func testMarkAsVerifiedMarksOnlyTheIdentityShown() throws {
        // Review M1: the list was shown, then the pin changed (Trust the new key on another device).
        let w = try world()
        let pins = try pinSet(pinsJson: nil, identityJson: w.alicePub, email: "alice@example.com", verified: false, now: 1)
        let shown = try XCTUnwrap(KeyPinsReader.people(pins).first)
        XCTAssertEqual(shown.fingerprint, w.aliceSigning.fingerprint())
        let marked = try XCTUnwrap(try KeyPinsReader.markingVerified(pins, userId: w.aliceId, identityHash: shown.identityHash))
        XCTAssertEqual(KeyPinsReader.people(marked).first?.verified, true)
        let impostor = try createAccount(accountId: w.aliceId, password: "correct horse battery", withSecretKey: false).account
        let changed = try pinSet(pinsJson: pins, identityJson: try impostor.newSigningIdentity().identity.publicIdentityJson(),
                                 email: "alice@example.com", verified: false, now: 2)
        XCTAssertThrowsError(try KeyPinsReader.markingVerified(changed, userId: w.aliceId, identityHash: shown.identityHash)) { e in
            XCTAssertEqual(errorMessage(e), SharingText.keysChangedCompareAgain)
        }
        XCTAssertNil(try KeyPinsReader.markingVerified(pins, userId: "nobody", identityHash: shown.identityHash))
    }

    func testMemoryRoundTripsAndKnowsItsServerVersion() throws {
        var m = SharingMemoryRecord()
        XCTAssertTrue(m.isEmpty)
        m.userId = "me"
        m.pinsSeq = 4
        m.sealedPins = "s"
        m.uploaded = false
        m.rosters = ["v": #"{"version":2}"#]
        m.signed = ["v"]
        XCTAssertEqual(m.serverBase, 3)
        let back = try JSONDecoder().decode(SharingMemoryRecord.self, from: try JSONEncoder().encode(m))
        XCTAssertEqual(back, m)
        XCTAssertFalse(back.isEmpty)
        // A damaged record reads as empty fields, never fails.
        let damaged = try JSONDecoder().decode(SharingMemoryRecord.self, from: Data(#"{"pins_seq":"x","rosters":3}"#.utf8))
        XCTAssertTrue(damaged.isEmpty)
        let mem = InMemorySharingMemory()
        mem.save("a", m)
        XCTAssertEqual(mem.load("a"), m)
        mem.clear("a")
        XCTAssertTrue(mem.load("a").isEmpty)
    }

    func testMemoryWritesMergeInsteadOfOverwriting() {
        // Review M3: the app and the AutoFill extension each save the copy they loaded earlier.
        var stored = SharingMemoryRecord()
        stored.userId = "me"
        stored.pinsSeq = 5
        stored.sealedPins = "five"
        stored.rosters = ["a": #"{"version":3}"#, "b": #"{"version":1}"#]
        stored.signed = ["a"]
        var stale = SharingMemoryRecord()
        stale.userId = "me"
        stale.pinsSeq = 4
        stale.sealedPins = "four"
        stale.rosters = ["a": #"{"version":2}"#, "b": #"{"version":2}"#, "c": #"{"version":1}"#]
        stale.signed = ["c"]
        let merged = stored.merging(stale)
        XCTAssertEqual(merged.pinsSeq, 5)
        XCTAssertEqual(merged.sealedPins, "five")
        XCTAssertEqual(merged.rosters["a"], #"{"version":3}"#)
        XCTAssertEqual(merged.rosters["b"], #"{"version":2}"#)
        XCTAssertEqual(merged.rosters["c"], #"{"version":1}"#)
        XCTAssertEqual(Set(merged.signed), ["a", "c"])
        // The same version: the copy the server has wins over one that still has to be sent.
        var local = stored
        local.uploaded = false
        local.sealedPins = "five-local"
        XCTAssertEqual(local.merging(stored).sealedPins, "five")
        XCTAssertEqual(stored.merging(local).sealedPins, "five")
        // A record without sealed pins never replaces one with them.
        var none = stored
        none.pinsSeq = 9
        none.sealedPins = nil
        XCTAssertEqual(stored.merging(none).sealedPins, "five")
        // Another account's record is replaced, not merged.
        var other = SharingMemoryRecord()
        other.userId = "someone-else"
        other.signed = ["z"]
        XCTAssertEqual(stored.merging(other), other)
        let mem = InMemorySharingMemory()
        mem.save("acc", stored)
        mem.save("acc", stale)
        XCTAssertEqual(mem.load("acc"), merged)
    }

    func testMemoryBelongsToTheAccountTheCoreAuthenticated() {
        // Review L3: "Change server" keeps the local account id; the memory of the old account
        // isn't used for the new one.
        var r = SharingMemoryRecord()
        r.userId = "old"
        r.server = "https://a.example"
        r.signed = ["v"]
        XCTAssertTrue(r.owned(by: "new", server: "https://a.example").isEmpty)
        XCTAssertTrue(r.owned(by: "old", server: "https://b.example").isEmpty)
        XCTAssertEqual(r.owned(by: "old", server: "https://a.example"), r)
        var unowned = SharingMemoryRecord()
        unowned.signed = ["v"]
        XCTAssertEqual(unowned.owned(by: "me", server: "s").userId, "me")
        XCTAssertEqual(unowned.owned(by: "me", server: "s").signed, ["v"])
    }

    func testRefusedVaultNamesAreCleaned() {
        // Review L5: a vault name is the server's claim.
        let r = RefusedVault(id: "v", name: "Fam\u{202E}ily\n\u{0007}" + String(repeating: "x", count: 100), reason: .unverified)
        XCTAssertFalse(r.name?.contains("\u{202E}") ?? true)
        XCTAssertFalse(r.name?.contains("\n") ?? true)
        XCTAssertLessThanOrEqual(r.name?.count ?? 0, 65, "64 and an ellipsis")
        XCTAssertNil(RefusedVault(id: "v", name: "\u{200B}", reason: .unverified).name)
    }

    func testReviewsAreReadAndKnowWhatStopsThem() throws {
        let w = try world()
        let text = try rosterReview(vaultId: w.vaultId, previous: w.roster, signerJson: w.alicePub,
                                    membersJson: JSON.array([Self.member(w.alicePub, "owner"), Self.member(w.bobPub, "admin")]).text, pinsJson: nil)
        let r = try XCTUnwrap(MemberReview.read(text))
        XCTAssertFalse(r.first)
        XCTAssertFalse(r.blocked)
        XCTAssertEqual(r.version, 2)
        XCTAssertEqual(r.changed.map(\.userId), [w.bobId])
        XCTAssertEqual(r.changed.first?.change, "role_changed")
        let first = try XCTUnwrap(MemberReview.read(try rosterReview(vaultId: w.vaultId, previous: nil, signerJson: w.alicePub,
                                                                       membersJson: JSON.array([Self.member(w.alicePub, "owner")]).text, pinsJson: nil)))
        XCTAssertTrue(first.first)
        XCTAssertEqual(first.version, 1)
        XCTAssertEqual(first.members.first?.isSelf, true)
        let missing = try XCTUnwrap(MemberReview.read(try rosterReview(vaultId: w.vaultId, previous: w.roster, signerJson: w.alicePub,
                                                                         membersJson: JSON.array([Self.member(w.alicePub, "owner")]).text, pinsJson: nil)))
        XCTAssertEqual(missing.missing.map(\.userId), [w.bobId])
    }

    func testEmergencyAccessCountsAVaultWithSignedHistoryAsShared() {
        // Review M4.
        let v = Emergency.OwnVault(id: "v", role: .owner, keyKind: VaultInfo.accountKeyKind)
        XCTAssertTrue(Emergency.isPersonal(v, members: ["me"], me: "me"))
        XCTAssertFalse(Emergency.isPersonal(v, members: ["me"], me: "me", signedHistory: true))
        XCTAssertFalse(Emergency.isPersonal(v, members: ["me", "x"], me: "me"))
    }

    func testKeyReplacementConfirmationWording() {
        let one = KeyReplacement(confirm: [KeyReplacement.Confirm(id: "f", name: "Family", people: ["bob@example.com"], userIds: ["b"])])
        XCTAssertEqual(one.confirmText, "bob@example.com is no longer a member of Family. Replace the key without them?")
        XCTAssertEqual(one.confirmedIds, ["f": ["b"]])
        let two = KeyReplacement(confirm: [KeyReplacement.Confirm(id: "f", name: "Family", people: ["a@x", "b@x"])])
        XCTAssertEqual(two.confirmText, "a@x, b@x are no longer members of Family. Replace the key without them?")
        XCTAssertNil(KeyReplacement().confirmText)
        let unknown = KeyReplacement(confirm: [KeyReplacement.Confirm(id: "f", name: "Family", people: [SharingText.unknownMember])])
        XCTAssertEqual(unknown.confirmText, "A former member is no longer a member of Family. Replace the key without them?")
        XCTAssertEqual(SharingText.membersDiffer(["carol@example.com"]),
                       "The server lists members your vault's signed member list doesn't: carol@example.com. PassAuth didn't change the key.")
        XCTAssertEqual(SharingText.refusedNotice([RefusedVault(id: "a", name: nil, reason: .unverified)]),
                       "PassAuth couldn't verify a shared vault, so it isn't shown.")
        XCTAssertNil(SharingText.refusedNotice([]))
        XCTAssertTrue(SharingText.refusal(.admission("left")).hasPrefix("You left this vault"))
        XCTAssertEqual(SharingText.refusal(.paused), SharingText.pausedRefusal)
    }

    func testIdentityJsonIsBuiltFieldByField() throws {
        let row = try JSON.parse(#"{"id":"u1","user_id":"u1","email":"x","public_key":"pk","signing_key":null,"x25519_signature":"xs","extra":1}"#)
        let built = try JSON.parse(try XCTUnwrap(SharingIdentity.json(row)))
        XCTAssertEqual(built, ["user_id": "u1", "public_key": "pk", "signing_key": .null, "identity_signature": .null, "x25519_signature": "xs"])
        XCTAssertNil(SharingIdentity.json(try JSON.parse(#"{"user_id":"u1"}"#)))
        XCTAssertNil(SharingIdentity.json(nil))
    }

    // MARK: Final review fixes (pure)

    func testHeadingsLeadWithThePinnedSignerEmail() {
        // L-E: a signer pinned as alice@example.com is named so, whatever the server lists; one not
        // pinned yet only as "someone listed by your server as …".
        let by = SyncInvitation.Sharer(id: "u1", email: "mallory@evil.example", name: "Alice")
        let pinned = SignerInfo(userId: "u1", email: "mallory@evil.example", name: "Alice", fingerprint: "F", deleted: false, pin: .unverified,
                                identity: "{}", pinnedEmail: "alice@example.com")
        let inv = Invitation(vaultId: "v", role: "write", name: "Family", invitedBy: by, trust: .signed(pinned))
        XCTAssertEqual(InvitationText.sharerHeading(inv), "alice@example.com")
        XCTAssertTrue(InvitationText.from(inv).hasPrefix("From alice@example.com"))
        XCTAssertTrue(InvitationText.notice([inv])?.hasPrefix("Alice@example.com invited you") ?? false)
        let fresh = SignerInfo(userId: "u1", email: "alice@example.com", name: "Alice", fingerprint: "F", deleted: false, pin: .new, identity: "{}")
        let first = Invitation(vaultId: "v", role: "write", name: "Family", invitedBy: by, trust: .signed(fresh))
        XCTAssertEqual(InvitationText.sharerHeading(first), "someone listed by your server as Alice (mallory@evil.example)")
        let unsigned = Invitation(vaultId: "v", role: "write", name: "Family", invitedBy: by, trust: .unsigned)
        XCTAssertTrue(InvitationText.sharerHeading(unsigned).hasPrefix("someone listed by your server as"))
        let plain = Invitation(vaultId: "v", role: "write", name: "Family", invitedBy: by)
        XCTAssertEqual(InvitationText.sharerHeading(plain), "Alice (mallory@evil.example)", "servers without signed sharing: as before")
    }

    func testTrustingANewKeyPinsTheEmailShown() {
        // L-F: the sheet shows the pinned email and pins exactly it (the server's listing is shown apart).
        let s = SignerInfo(userId: "u1", email: "bob@new.example", name: "Bob", fingerprint: "F", deleted: false, pin: .changed, identity: "{}",
                           pinnedEmail: "bob@example.com")
        XCTAssertEqual(s.shownName, "bob@example.com")
        XCTAssertEqual(s.trustEmail, "bob@example.com")
        XCTAssertEqual(SharingText.trustSavedAs(s), "PassAuth saves the new key for bob@example.com.")
        XCTAssertEqual(s.otherListedEmail, "bob@new.example")
        let unpinned = SignerInfo(userId: "u2", email: "Carol@Example.com", name: "", fingerprint: "F", deleted: false, pin: .changed, identity: "{}")
        // Pins keep one form only: the core's `normalize_email` (round 4).
        XCTAssertEqual(unpinned.trustEmail, "carol@example.com")
        let invisible = SignerInfo(userId: "u3", email: "Al\u{200B}ice@B\u{00FC}cher.example.", name: "", fingerprint: "F", deleted: false, pin: .new,
                                   identity: "{}")
        XCTAssertEqual(invisible.listedEmail, normalizeEmail(email: "alice@b\u{00FC}cher.example"))
        XCTAssertEqual(invisible.pinEmailToWrite, "alice@xn--bcher-kva.example")
        XCTAssertEqual(SharingText.trustSavedAs(unpinned), "PassAuth saves the new key for carol@example.com.")
    }

    func testAnInvitationThatChangedIsAnotherDecision() {
        // M-A, as a pure check: another key epoch pin, roster or signer is another decision.
        let signer = SignerInfo(userId: "u1", email: "a@b.c", name: "", fingerprint: "F", deleted: false, pin: .unverified, identity: "{}",
                                pinnedEmail: "a@b.c", identityHash: "H1")
        var a = Invitation(vaultId: "v", role: "write", name: "Family", trust: .signed(signer))
        a.acceptance = Acceptance(epochPin: "{\"k\":1}", rosterVersion: 1, roster: "r", rosterHash: "R1", signer: nil)
        XCTAssertTrue(Invitation.sameDecision(a, a))
        var b = a
        b.acceptance = Acceptance(epochPin: "{\"k\":2}", rosterVersion: 1, roster: "r", rosterHash: "R1", signer: nil)
        XCTAssertFalse(Invitation.sameDecision(a, b), "another key")
        b = a
        b.acceptance = Acceptance(epochPin: "{\"k\":1}", rosterVersion: 1, roster: "r2", rosterHash: "R2", signer: nil)
        XCTAssertFalse(Invitation.sameDecision(a, b), "another member list")
        let other = SignerInfo(userId: "u1", email: "a@b.c", name: "", fingerprint: "G", deleted: false, pin: .unverified, identity: "{}",
                               pinnedEmail: "a@b.c", identityHash: "H2")
        b = a
        b.trust = .signed(other)
        XCTAssertFalse(Invitation.sameDecision(a, b), "another signer")
        b = a
        b.consent = .added
        XCTAssertFalse(Invitation.sameDecision(a, b), "a consent isn't the invitation shown")
    }

    func testTheKeychainMemoryNeverWritesOverWhatItCouldntRead() throws {
        // L-C: a refused read is unknown, never empty; a write that can't read first or can't take
        // the lock waits and is tried again with the next save.
        final class FakeKeychain: @unchecked Sendable {
            var result: Keychain.ReadResult = .failed(-25308)
            var writes = 0
        }
        let fake = FakeKeychain()
        let store = KeychainSharingMemory.Store(lookup: { _ in fake.result }, write: { _, d in
            fake.writes += 1
            fake.result = .found(d)
            return true
        }, delete: { _ in fake.result = .notFound })
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-memory-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let memory = KeychainSharingMemory(lockDirectory: dir, keychain: store, lockTimeout: 0.1)
        XCTAssertTrue(memory.load("acc").unreadable)
        XCTAssertFalse(memory.load("acc").isEmpty, "unknown counts as memory")
        var one = SharingMemoryRecord()
        one.signed = ["v1"]
        XCTAssertFalse(memory.save("acc", one))
        XCTAssertEqual(fake.writes, 0, "nothing written over what couldn't be read")
        // Readable now, but the other process holds the lock: still not written.
        fake.result = .notFound
        let held = try XCTUnwrap(FileLock.tryAcquire(FileLock.url("signed-sharing", directory: dir)))
        var two = SharingMemoryRecord()
        two.signed = ["v2"]
        XCTAssertFalse(memory.save("acc", two))
        XCTAssertEqual(fake.writes, 0)
        XCTAssertEqual(Set(memory.load("acc").signed), ["v1", "v2"], "this process still sees what waits")
        held.release()
        XCTAssertTrue(memory.save("acc", SharingMemoryRecord()))
        XCTAssertEqual(fake.writes, 1)
        guard case .found(let d) = fake.result else { return XCTFail("not stored") }
        XCTAssertEqual(Set(try JSONDecoder().decode(SharingMemoryRecord.self, from: d).signed), ["v1", "v2"])
    }

    func testMemoryKeepsThePendingIdentityAndTheConsentList() throws {
        var r = SharingMemoryRecord()
        r.pendingIdentity = "H"
        r.pendingRecord = "{}"
        r.missing = ["v1"]
        r.missingDevice = true
        let back = try JSONDecoder().decode(SharingMemoryRecord.self, from: try JSONEncoder().encode(r))
        XCTAssertEqual(back, r)
        XCTAssertFalse(back.isEmpty)
        // nil from a writer that didn't change it keeps the stored list; empty clears it.
        var other = SharingMemoryRecord()
        other.signed = ["v2"]
        XCTAssertEqual(r.merging(other).missing, ["v1"])
        other.missing = []
        XCTAssertEqual(r.merging(other).missing, [])
        XCTAssertEqual(r.merging(other).pendingIdentity, "H")
    }

    // MARK: Round 4 (core API and the cross-client rules)

    /// A vault the account saw signed up to roster version 1 (its hash pinned), served by a
    /// server on a device with no remembered roster as a chain re-signed from version 1 by an
    /// account it made up ("puppet signer"): the fetched chain's hashes (`chain_hashes`) show
    /// version 1 isn't the pinned one, so it is refused (roster_forked). Without them version 2
    /// would pass as the next roster.
    func testAFetchedChainIsCheckedAgainstThePinnedRosterHash() throws {
        let w = try world()
        let pinnedHash = try rosterHash(rosterJson: w.roster)
        var pins = try pinSet(pinsJson: nil, identityJson: w.alicePub, email: "alice@example.com", verified: false, now: 1)
        pins = try pinsAccept(pinsJson: pins, observationJson: SignedSharing.observation(
            vaultId: w.vaultId, kind: "sealed", epochPin: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0), rosterVersion: 1,
            rosterHash: pinnedHash, signedShare: true, paused: false))
        let malloryId = try newId()
        let mallory = try createAccount(accountId: malloryId, password: "correct horse battery", withSecretKey: false).account
        let puppet = try mallory.newSigningIdentity().identity
        let puppetKey = try mallory.newVaultKey(vaultId: w.vaultId).key
        let members = [Self.member(try puppet.publicIdentityJson(), "owner"), Self.member(w.bobPub, "write")]
        let v1 = try Self.signRoster(puppet, key: puppetKey, vault: w.vaultId, previous: nil, epoch: 1, members: members)
        let v2 = try Self.signRoster(puppet, key: puppetKey, vault: w.vaultId, previous: v1, epoch: 1, members: members)
        let share = try puppet.sealAndSignShare(vaultKey: puppetKey, vaultId: w.vaultId, recipientJson: w.bobPub, role: "write", keyEpoch: 1)
        let row = SyncVault(id: w.vaultId, meta: "", role: "write", wrappedKey: share.sealedKey, keyKind: "sealed", keyEpoch: 1, seq: 2,
                            share: try shareJSON(share.signature, puppet, email: "mallory@example.com"), memberRoster: v2, memberRosterSeq: 2)
        XCTAssertEqual(try check(w, row, pins: pins, newer: [v1, v2]), .refused(.admission("roster_forked")))
        // The same observation without the chain (what an app sending no `chain_hashes` would say): passes.
        let key = try w.bob.openVaultKey(vaultId: w.vaultId, wrapped: share.sealedKey, kind: "sealed", keyEpoch: 1, legacyAllowed: true)
        let bare = try XCTUnwrap(SignedSharing.admit(pins, vaultId: w.vaultId, kind: "sealed", epochPin: try key.epochPinJson(vaultId: w.vaultId, keyEpoch: 1),
                                                     rosterVersion: 2, rosterHash: try rosterHash(rosterJson: v2), signedShare: true, paused: false))
        XCTAssertEqual(bare.str("status"), "ok")
        // An invitation's chain from version 1 carries them too.
        let inv = SyncInvitation(vaultId: w.vaultId, role: "write", wrappedKey: share.sealedKey, meta: "m", keyEpoch: 1,
                                 share: try shareJSON(share.signature, puppet, email: "mallory@example.com"), memberRoster: v2, memberRosterSeq: 2)
        let checked = SignedSharing.checkInvitation(inv, key: key, me: w.bobSelf, pins: pins, remembered: nil, newer: [v1, v2], tooLarge: false)
        XCTAssertEqual(checked.0, .refused)
        let fresh = SignedSharing.checkInvitation(inv, key: key, me: w.bobSelf, pins: nil, remembered: nil, newer: [v1, v2], tooLarge: false)
        XCTAssertEqual(fresh.1?.chainHashes, ["1": try rosterHash(rosterJson: v1), "2": try rosterHash(rosterJson: v2)])
    }

    /// A vault the account held with its own key wrap, now served sealed with a newer key signed by
    /// someone: consent (replaced, own), never silently used; the wording names the signer and
    /// says it was the user's own vault.
    func testAnOwnVaultServedSealedWithANewKeyNeedsConsentAndSaysSo() throws {
        let w = try world()
        let own = try XCTUnwrap(SignedSharing.observe(nil, vaultId: w.vaultId, kind: "account", epochPin: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0),
                                                      rosterVersion: nil, rosterHash: nil, signedShare: false, paused: false)).pins
        XCTAssertEqual(try JSON.parse(try XCTUnwrap(own))["epochs"]?[w.vaultId]?["own"]?.bool, true)
        let next = try w.alice.newVaultKey(vaultId: w.vaultId).key
        let share = try w.aliceSigning.sealAndSignShare(vaultKey: next, vaultId: w.vaultId, recipientJson: w.bobPub, role: "write", keyEpoch: 1)
        let roster = try Self.signRoster(w.aliceSigning, key: next, vault: w.vaultId, previous: nil, epoch: 1,
                                         members: [Self.member(w.alicePub, "owner"), Self.member(w.bobPub, "write")])
        let row = SyncVault(id: w.vaultId, meta: "", role: "write", wrappedKey: share.sealedKey, keyKind: "sealed", keyEpoch: 1, seq: 2,
                            share: try shareJSON(share.signature, w.aliceSigning), memberRoster: roster, memberRosterSeq: 1)
        let got = try check(w, row, pins: own, newer: [roster])
        guard case .consent(let a, false, true, true, let signer?) = got else { return XCTFail("\(got)") }
        XCTAssertEqual(signer.pin, .new)
        XCTAssertEqual(a.kind, "sealed")
        // Accepting it writes the newer key with its roster (`pins_accept`).
        let accepted = try JSON.parse(try pinsAccept(pinsJson: own, observationJson: a.observation(vaultId: w.vaultId, paused: false)))
        XCTAssertEqual(accepted["epochs"]?[w.vaultId]?["key_epoch"]?.number, 1)
        XCTAssertEqual(accepted["epochs"]?[w.vaultId]?["roster_hash"]?.string, try rosterHash(rosterJson: roster))
        XCTAssertEqual(SharingText.replaced("Home", signer: signer),
                       "The key of \u{201C}Home\u{201D} was replaced and signed by someone listed by your server as alice@example.com for the first time. Compare their fingerprint before you accept.")
        XCTAssertTrue(SharingText.ownVault("Home").hasPrefix("\u{201C}Home\u{201D} was your own vault."))
        let pinned = SignerInfo(userId: "u", email: "x@evil.example", name: "", fingerprint: "F", deleted: false, pin: .unverified, identity: "{}",
                                pinnedEmail: "Alice@Example.com")
        XCTAssertEqual(pinned.heading, "alice@example.com")
        XCTAssertTrue(SharingText.replaced(nil).contains("by an app that doesn't sign yet"))
    }

    /// An upgraded signer (pinned legacy, now with a cross-signed signing key) keeps the pinned
    /// email and its "verified" mark (cross-client rule 4).
    func testAnUpgradedSignerKeepsThePinnedEmailAndVerified() throws {
        let w = try world()
        var pins = try pinSet(pinsJson: nil, identityJson: try w.alice.legacyIdentityJson(), email: "alice@corp.example", verified: true, now: 1)
        pins = try pinsSetEpoch(pinsJson: pins, vaultId: w.vaultId, currentJson: try w.key.epochPinJson(vaultId: w.vaultId, keyEpoch: 0), rosterVersion: 1)
        let got = try check(w, try bobRow(w), pins: pins, remembered: w.roster)
        guard case .ok(.signed(let s), _, let p?) = got else { return XCTFail("\(got)") }
        XCTAssertEqual(s.pin, .upgraded)
        XCTAssertEqual(s.pinEmailToWrite, "alice@corp.example")
        XCTAssertTrue(s.pinVerifiedToWrite)
        let pin = try JSON.parse(p)["pins"]?.array.first { $0.str("user_id") == w.aliceId }
        XCTAssertEqual(pin?["email"]?.string, "alice@corp.example")
        XCTAssertEqual(pin?["verified"]?.bool, true)
        XCTAssertEqual(pin?["signing_key"]?.string, try JSON.parse(w.alicePub).str("signing_key"))
        // Someone new is pinned with the (normalized) email the server lists, not verified.
        let fresh = SignerInfo(userId: "u", email: " Bob@B\u{00FC}cher.Example ", name: "", fingerprint: "F", deleted: false, pin: .new, identity: "{}")
        XCTAssertEqual(fresh.pinEmailToWrite, "bob@xn--bcher-kva.example")
        XCTAssertFalse(fresh.pinVerifiedToWrite)
    }

    /// Accepting is bound to the email shown for the signer (cross-client rule 4, review L1).
    func testTheEmailShownForTheSignerIsPartOfTheDecision() {
        func signer(_ listed: String, pinned: String? = nil) -> SignerInfo {
            SignerInfo(userId: "u1", email: listed, name: "", fingerprint: "F", deleted: false, pin: pinned == nil ? .new : .unverified, identity: "{}",
                       pinnedEmail: pinned, identityHash: "H1")
        }
        func inv(_ s: SignerInfo) -> Invitation {
            var i = Invitation(vaultId: "v", role: "write", name: "Family", trust: .signed(s))
            i.acceptance = Acceptance(epochPin: "{\"k\":1}", rosterVersion: 1, roster: "r", rosterHash: "R1", signer: s.needsPin ? s : nil)
            return i
        }
        XCTAssertTrue(Invitation.sameDecision(inv(signer("alice@example.com")), inv(signer("Alice@Example.com"))), "one form")
        XCTAssertFalse(Invitation.sameDecision(inv(signer("alice@example.com")), inv(signer("mallory@example.com"))), "another listed email")
        XCTAssertFalse(Invitation.sameDecision(inv(signer("x@y.z", pinned: "alice@example.com")), inv(signer("x@y.z", pinned: "bob@example.com"))))
        var own = inv(signer("alice@example.com"))
        own.own = true
        XCTAssertFalse(Invitation.sameDecision(inv(signer("alice@example.com")), own))
    }

    /// Decline only for invitations and signed consent that names a signer (cross-client rule 1);
    /// consent headings never say "someone whose account was deleted".
    func testUnsignedConsentNeverOffersDeclineAndNamesTheServer() {
        let s = SignerInfo(userId: "u1", email: "alice@example.com", name: "", fingerprint: "F", deleted: false, pin: .unverified, identity: "{}",
                           pinnedEmail: "alice@example.com")
        var invitation = Invitation(vaultId: "v", role: "read", name: "Family", trust: .unsigned)
        XCTAssertTrue(invitation.canDecline, "an invitation can always be declined")
        var added = Invitation(vaultId: "v", role: "read", name: "Family", trust: .unsigned)
        added.consent = .added
        XCTAssertFalse(added.canDecline)
        XCTAssertEqual(InvitationText.sharerHeading(added), "your server")
        XCTAssertEqual(InvitationText.from(added), "Listed by your server")
        XCTAssertFalse(InvitationText.notice([added])?.contains("deleted") ?? true)
        XCTAssertTrue(InvitationText.notice([added])?.hasPrefix("Your server lists the shared vault \"Family\"") ?? false)
        XCTAssertEqual(SharingText.consentUnsigned, "This vault isn't signed, so PassAuth can't accept it. Ask the vault's owner to sign this vault.")
        var signed = Invitation(vaultId: "v", role: "read", name: "Family", trust: .signed(s))
        signed.consent = .added
        XCTAssertTrue(signed.canDecline)
        XCTAssertEqual(InvitationText.sharerHeading(signed), "alice@example.com")
        signed.consent = .replaced
        XCTAssertFalse(signed.canDecline, "a replaced key is kept locked instead")
        signed.consent = .added
        signed.declineHidden = true
        XCTAssertFalse(signed.canDecline)
        invitation.trust = .refused
        XCTAssertTrue(invitation.canDecline)
        XCTAssertEqual(SharingText.refusal(.checking), SharingText.checking)
        XCTAssertTrue(SharingText.checking.hasPrefix("PassAuth is still checking this shared vault"))
        XCTAssertEqual(SharingText.refusedNotice([RefusedVault(id: "v", name: nil, reason: .checking)]),
                       "A shared vault isn't shown until PassAuth finishes checking it.")
        XCTAssertEqual(Acceptance(epochPin: #"{"key_epoch":0,"key_id":"abcdefghijklmnopqrstuvwxyz"}"#, rosterVersion: nil, roster: nil, signer: nil).shownKeyId,
                       "abcd-efgh-ijkl-mnop")
    }

    func testTheRateLimitOnKeyReplacementsIsSaid() {
        XCTAssertEqual(SharingText.keyReplacementLimited(120),
                       "This vault's key was replaced too often in the last hour, so your server didn't take another replacement. Try again in 2 minutes.")
        XCTAssertTrue(SharingText.keyReplacementLimited(nil).hasSuffix("Try again later."))
    }

    /// The device memory's round-4 fields: `proven` keeps the checks on, `seen` doesn't; the
    /// grandfathering candidates are written once; settling drops the pending identity for good;
    /// tombstones waiting to be written survive a restart.
    func testMemoryProvenSeenCandidatesSettledAndTombstones() throws {
        var r = SharingMemoryRecord()
        r.seen = ["v1"]
        XCTAssertTrue(r.isEmpty, "a list of vaults shown doesn't turn the checks on")
        r.proven = true
        XCTAssertFalse(r.isEmpty, "a server that showed it signs does")
        r.candidates = ["v1"]
        r.pendingIdentity = "H"
        r.tombstones = ["gone": 3]
        let back = try JSONDecoder().decode(SharingMemoryRecord.self, from: try JSONEncoder().encode(r))
        XCTAssertEqual(back, r)
        var other = SharingMemoryRecord()
        other.seen = ["v2", "v1"]
        other.candidates = ["v9"]
        let merged = r.merging(other)
        XCTAssertEqual(merged.seen, ["v1", "v2"])
        XCTAssertEqual(merged.candidates, ["v1"], "recorded once")
        XCTAssertTrue(merged.proven)
        XCTAssertEqual(merged.tombstones, ["gone": 3])
        var done = SharingMemoryRecord()
        done.settled = true
        done.tombstones = [:]
        let settled = merged.merging(done)
        XCTAssertNil(settled.pendingIdentity)
        XCTAssertNil(settled.candidates)
        XCTAssertEqual(settled.tombstones, [:])
        // A later writer's pending identity can't come back once settled.
        var late = SharingMemoryRecord()
        late.pendingIdentity = "H2"
        XCTAssertNil(settled.merging(late).pendingIdentity)
        var many = SharingMemoryRecord()
        many.seen = (0..<(SharingMemoryRecord.maxSeen + 5)).map { "v\($0)" }
        XCTAssertEqual(SharingMemoryRecord().merging(many).seen?.count, SharingMemoryRecord.maxSeen)
    }
}
