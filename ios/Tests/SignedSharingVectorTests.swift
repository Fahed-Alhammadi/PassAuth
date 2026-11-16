import Foundation
import PassAuthCore
@testable import PassAuthKit
import XCTest

/// The `signedSharing` golden vectors (testdata/vectors.json, made by the core and cross-checked
/// there independently by testdata/generate-vectors.mjs) through this app's bindings of the same
/// core and its own wrappers, as `crates/core/tests/vectors.rs` checks them natively: account
/// wraps (v1/v2, epochs) and key ids, identities with their X25519 cross-signatures (a forged
/// upgrade refused) and fingerprints (also from a pin's hash alone), share signatures, member
/// rosters signed again through the review byte for byte, key commitments, roster chains and
/// heads (bound to the vault id), member differences, member and signer roles, key pins and their
/// checks, reviews, epoch pins, tombstones, grandfathering, admissions, legacy wraps and the own
/// identity. Also run by the macOS AutoFill extension's tests (desktop/macos/project.yml).
final class SignedSharingVectorTests: XCTestCase {
    private typealias Object = [String: Any]

    nonisolated(unsafe) private static let vectors: Object = {
        guard let url = Bundle(for: SignedSharingVectorTests.self).url(forResource: "vectors", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? Object,
              let section = object["signedSharing"] as? Object
        else { return [:] }
        return section
    }()

    private var v: Object { Self.vectors }
    private func list(_ name: String) -> [Object] { v[name] as? [Object] ?? [] }
    private func text(_ o: Any?) throws -> String {
        String(data: try JSONSerialization.data(withJSONObject: o ?? NSNull(), options: [.fragmentsAllowed]), encoding: .utf8) ?? ""
    }
    private func object(_ s: String) -> NSDictionary? {
        (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? NSDictionary
    }
    private func number(_ o: Any?) -> UInt64 { (o as? NSNumber)?.uint64Value ?? 0 }
    private func optNumber(_ o: Any?) -> UInt64? { (o as? NSNumber)?.uint64Value }
    private func str(_ o: Any?) -> String? { o as? String }

    /// The core's error code (or description), as the vectors name it.
    private func code(_ error: Error) -> String {
        guard let e = error as? CoreError else { return "\(error)" }
        switch e {
        case .DecryptFailed(let m), .PasswordRequired(let m), .WeakKdf(let m), .KdfTooStrong(let m), .PhraseMismatch(let m),
             .WrongCode(let m), .TooManyWrongCodes(let m), .NotConfirmed(let m), .BadSignature(let m), .IdentityMismatch(let m),
             .Rollback(let m), .RosterForked(let m), .RosterUnauthorized(let m), .TooLarge(let m), .ReviewMismatch(let m), .Invalid(let m):
            return m
        }
    }

    /// A case's `expected` or `error` against what the binding did.
    private func outcome<T>(_ c: Object, _ label: String, _ body: () throws -> T, same: (T, Any?) -> Bool) {
        do {
            let got = try body()
            XCTAssertNil(c["error"], "\(label): expected \(c["error"] ?? "") but got \(got)")
            XCTAssertTrue(same(got, c["expected"]), "\(label): got \(got), expected \(c["expected"] ?? "nil")")
        } catch {
            XCTAssertEqual(code(error), c["error"] as? String, label)
        }
    }

    private struct Who {
        let account: Account
        let signing: SigningIdentity
    }

    private func accounts() throws -> [String: Who] {
        var out: [String: Who] = [:]
        for a in list("accounts") {
            let id = a["id"] as? String ?? ""
            let bytes = try XCTUnwrap(SharingIdentity.base64url(a["sessionBytes"] as? String ?? ""))
            let account = try accountFromSessionBytes(accountId: id, bytes: bytes)
            out[a["name"] as? String ?? ""] = Who(account: account, signing: try account.openSigningIdentity(recordJson: try text(a["record"])))
        }
        return out
    }

    /// An account's full or legacy identity as JSON (from the keys, as the core does).
    private func who(_ a: [String: Who], _ name: String, legacy: Bool) throws -> String {
        let w = try XCTUnwrap(a[name], name)
        return legacy ? try w.account.legacyIdentityJson() : try w.signing.publicIdentityJson()
    }

    private var vault: Object { v["vault"] as? Object ?? [:] }
    private var vaultId: String { vault["id"] as? String ?? "" }

    private func openKey(_ a: [String: Who], _ wrap: String, epoch: UInt64, legacy: Bool) throws -> VaultKey {
        try XCTUnwrap(a["alice"]).account.openVaultKey(vaultId: vaultId, wrapped: vault[wrap] as? String ?? "", kind: "account", keyEpoch: epoch,
                                                       legacyAllowed: legacy)
    }

    /// The members of a vector (`[name, role, legacy?, email?]`) as the core's roster input.
    private func members(_ a: [String: Who], _ raw: Any?, emails: Bool = true) throws -> String {
        let rows = try (raw as? [[Any]] ?? []).map { m -> Any in
            let name = m[0] as? String ?? "", role = m[1] as? String ?? ""
            let legacy = m.count > 2 ? (m[2] as? Bool ?? false) : false
            var o = object(try who(a, name, legacy: legacy)) as? [String: Any] ?? [:]
            o["role"] = role
            if emails, m.count > 3, let e = m[3] as? String { o["email"] = e }
            return o
        }
        return try text(rows)
    }

    func testSectionsAreThere() {
        for name in ["accounts", "openings", "identities", "shares", "rosters", "commitments", "chains", "heads", "memberDiffs", "rosterRoles",
                     "pinChecks", "reviews", "epochChecks", "pinsEpochChecks", "admissions", "accepts", "merges", "observations", "emails",
                     "legacyWraps"] {
            XCTAssertFalse(list(name).isEmpty, "no \(name) vectors")
        }
        for name in ["keyPins", "keyPinsWithEpoch", "keyPinsRaised", "keyPinsLeft", "keyPinsGrandfathered", "keyPinsWithheld", "keyPinsUnsigned", "keyPinsRosterMax", "keyPinsOwn", "mergedEpochs", "ownIdentity", "keyIds",
                     "forgedUpgrade"] {
            XCTAssertNotNil(v[name], name)
        }
    }

    func testAccountWrapsAndKeyIds() throws {
        let a = try accounts()
        for c in list("openings") {
            outcome(c, "opening \(c)", {
                try openKey(a, c["wrap"] as? String ?? "", epoch: number(c["keyEpoch"]), legacy: c["legacyAllowed"] as? Bool ?? false).keyId(vaultId: vaultId)
            }, same: { $0 == ($1 as? String) })
        }
        let ids = v["keyIds"] as? Object ?? [:]
        XCTAssertEqual(try openKey(a, "wrappedKeyV2", epoch: 0, legacy: false).keyId(vaultId: vaultId), ids["first"] as? String)
        XCTAssertEqual(try openKey(a, "secondKeyV2", epoch: 0, legacy: false).keyId(vaultId: vaultId), ids["second"] as? String)
        // The app writes v1 account wraps (every released app reads them).
        let key = try openKey(a, "wrappedKeyV2", epoch: 0, legacy: false)
        let rewrapped = try key.wrapFor(account: try XCTUnwrap(a["alice"]).account, vaultId: vaultId)
        XCTAssertEqual(try openKey(a, "wrappedKey", epoch: 9, legacy: true).keyId(vaultId: vaultId), ids["first"] as? String)
        XCTAssertNoThrow(try XCTUnwrap(a["alice"]).account.openVaultKey(vaultId: vaultId, wrapped: rewrapped, kind: "account", keyEpoch: 3, legacyAllowed: true))
    }

    func testIdentitiesAndFingerprints() throws {
        let a = try accounts()
        for i in list("identities") {
            let name = i["name"] as? String ?? ""
            XCTAssertEqual(object(try who(a, name, legacy: false)), i["publicIdentity"] as? NSDictionary, name)
            XCTAssertEqual(object(try who(a, name, legacy: true)), i["legacyIdentity"] as? NSDictionary, name)
            let info = try XCTUnwrap(object(try verifyIdentity(identityJson: try who(a, name, legacy: false))))
            XCTAssertEqual(info["hash"] as? String, i["hash"] as? String, name)
            XCTAssertEqual(info["legacy_hash"] as? String, i["legacyHash"] as? String, name)
            XCTAssertEqual(info["fingerprint"] as? String, i["fingerprint"] as? String, name)
            XCTAssertEqual(info["signing"] as? Bool, true)
            let legacy = try XCTUnwrap(object(try verifyIdentity(identityJson: try who(a, name, legacy: true))))
            XCTAssertEqual(legacy["hash"] as? String, i["legacyHash"] as? String)
            XCTAssertEqual(legacy["signing"] as? Bool, false)
            // The app's own fingerprint of a hash (pins keep only the hash).
            XCTAssertEqual(SharingIdentity.fingerprint(hash: i["hash"] as? String ?? ""), i["fingerprint"] as? String, name)
            XCTAssertEqual(SharingIdentity.fingerprint(hash: i["legacyHash"] as? String ?? ""), legacy["fingerprint"] as? String, name)
            let signing = try XCTUnwrap(a[name]).signing
            XCTAssertEqual(signing.fingerprint(), i["fingerprint"] as? String)
            XCTAssertEqual(signing.identityHash(), i["hash"] as? String)
            // The app builds the same identity from a server row (other fields, `id` instead of `user_id`).
            var row = i["publicIdentity"] as? [String: Any] ?? [:]
            row["id"] = row.removeValue(forKey: "user_id")
            row["email"] = "\(name)@example.com"
            let built = try XCTUnwrap(SharingIdentity.json(try JSON.parse(try text(row))))
            XCTAssertEqual(object(built), i["publicIdentity"] as? NSDictionary)
        }
        XCTAssertNil(SharingIdentity.fingerprint(hash: "AAAA"))
        // Review H1: someone else's X25519 key paired with another signing key doesn't verify.
        XCTAssertThrowsError(try verifyIdentity(identityJson: try text(v["forgedUpgrade"]))) { XCTAssertEqual(self.code($0), "bad_signature") }
        // A legacy identity of Bob served with a signing key but without the cross-signature.
        var stripped = object(try who(a, "bob", legacy: false)) as? [String: Any] ?? [:]
        stripped["x25519_signature"] = NSNull()
        XCTAssertThrowsError(try verifyIdentity(identityJson: try text(stripped)))
    }

    func testShares() throws {
        let a = try accounts()
        for s in list("shares") {
            let signer = s["signer"] as? String ?? "", recipient = s["recipient"] as? String ?? ""
            let role = s["role"] as? String ?? "", sealed = s["sealedKey"] as? String ?? "", sig = s["signature"] as? String ?? ""
            let epoch = number(s["keyEpoch"])
            let to = try who(a, recipient, legacy: s["recipientLegacy"] as? Bool ?? false)
            let vid = s["vaultId"] as? String ?? vaultId
            // Deterministic Ed25519: the binding signs the same bytes.
            XCTAssertEqual(try XCTUnwrap(a[signer]).signing.signShare(vaultId: vid, recipientJson: to, role: role, keyEpoch: epoch, sealedKey: sealed), sig)
            let info = try XCTUnwrap(object(try verifyShare(vaultId: vid, recipientJson: to, role: role, keyEpoch: epoch, sealedKey: sealed,
                                                             signerJson: try who(a, signer, legacy: false), signature: sig)))
            XCTAssertEqual(info["fingerprint"] as? String, list("identities").first { $0["name"] as? String == signer }?["fingerprint"] as? String)
            XCTAssertThrowsError(try verifyShare(vaultId: vid, recipientJson: to, role: role == "read" ? "write" : "read", keyEpoch: epoch,
                                                 sealedKey: sealed, signerJson: try who(a, signer, legacy: false), signature: sig)) { e in
                XCTAssertEqual(self.code(e), "bad_signature")
            }
            XCTAssertThrowsError(try verifyShare(vaultId: vid, recipientJson: to, role: role, keyEpoch: epoch + 1, sealedKey: sealed,
                                                 signerJson: try who(a, signer, legacy: false), signature: sig))
            // A legacy signer signs nothing.
            XCTAssertThrowsError(try verifyShare(vaultId: vid, recipientJson: to, role: role, keyEpoch: epoch, sealedKey: sealed,
                                                 signerJson: try who(a, signer, legacy: true), signature: sig))
        }
    }

    /// Every roster by name (valid ones signed again through the review first).
    private func rosters(_ a: [String: Who], key: VaultKey) throws -> [String: String] {
        var out: [String: String] = [:]
        for r in list("rosters") {
            let name = r["name"] as? String ?? ""
            let json = r["json"] as? String ?? ""
            XCTAssertEqual(try rosterHash(rosterJson: json), r["hash"] as? String, "roster \(name)'s hash")
            if r["rogue"] as? Bool != true {
                let signer = try XCTUnwrap(a[r["signer"] as? String ?? ""]).signing
                let previous = (r["previous"] as? String).flatMap { out[$0] }
                let list = try members(a, r["members"])
                let review = try XCTUnwrap(MemberReview.read(try rosterReview(vaultId: vaultId, previous: previous,
                                                                                signerJson: try signer.publicIdentityJson(), membersJson: list, pinsJson: nil)))
                XCTAssertEqual(review.version, number(r["version"]), name)
                let signed = try signer.signRoster(vaultKey: key, vaultId: vaultId, previous: previous, keyEpoch: number(r["keyEpoch"]),
                                                   membersJson: list, reviewed: review.digest)
                XCTAssertEqual(signed, json, "roster \(name)")
                XCTAssertTrue(try key.matchesRoster(vaultId: vaultId, rosterJson: json))
                XCTAssertFalse(try key.matchesRoster(vaultId: "00000000-0000-4000-8000-0000000000f2", rosterJson: json))
                XCTAssertEqual(SignedSharing.rosterEpoch(json), (r["keyEpoch"] as? NSNumber)?.int64Value)
                XCTAssertEqual(SignedSharing.rosterVersion(json), number(r["version"]))
                // Another list than the one reviewed is refused.
                if let other = try? members(a, (r["members"] as? [[Any]] ?? []).dropLast().map { $0 }), other != list {
                    XCTAssertThrowsError(try signer.signRoster(vaultKey: key, vaultId: vaultId, previous: previous, keyEpoch: number(r["keyEpoch"]),
                                                               membersJson: other, reviewed: review.digest))
                }
            }
            out[name] = json
        }
        return out
    }

    func testRostersCommitmentsChainsAndHeads() throws {
        let a = try accounts()
        let key = try openKey(a, "wrappedKeyV2", epoch: 0, legacy: false)
        let rosters = try rosters(a, key: key)
        let nameOf: (String) -> String = { json in rosters.first { $0.value == json }?.key ?? json }
        for c in list("commitments") {
            XCTAssertEqual(try key.commitment(vaultId: vaultId, keyEpoch: number(c["keyEpoch"])), c["commitment"] as? String)
        }
        let other = try XCTUnwrap(a["alice"]).account.newVaultKey(vaultId: vaultId).key
        XCTAssertFalse(try other.matchesRoster(vaultId: vaultId, rosterJson: try XCTUnwrap(rosters["v1"])))
        for c in list("chains") {
            let trusted = str(c["trusted"]).flatMap { rosters[$0] }
            let newer = (c["newer"] as? [String] ?? []).compactMap { rosters[$0] }
            let latest = rosters[c["latest"] as? String ?? ""] ?? ""
            outcome(c, "chain \(c)", {
                nameOf(try verifyRosterChain(vaultId: c["vault"] as? String ?? "", trusted: trusted, newer: newer, latest: latest))
            }, same: { $0 == ($1 as? String) })
        }
        for c in list("heads") {
            let remembered = str(c["remembered"]).flatMap { rosters[$0] }
            let latest = str(c["latest"]).flatMap { rosters[$0] }
            let vid = c["vault"] as? String ?? ""
            outcome(c, "head \(c)", { try rosterHead(vaultId: vid, remembered: remembered, latest: latest) },
                    same: { self.object($0) == ($1 as? NSDictionary) })
            // The app's wrapper agrees (nil where the core refuses).
            let wrapped = SignedSharing.head(vid, remembered: remembered, latest: latest)
            if let want = c["expected"] as? NSDictionary {
                XCTAssertEqual(wrapped?.status, want["status"] as? String)
                XCTAssertEqual(wrapped?.after, (want["after"] as? NSNumber)?.int64Value ?? 0)
            } else {
                XCTAssertNil(wrapped)
            }
        }
        for c in list("memberDiffs") {
            let roster = try XCTUnwrap(rosters[c["roster"] as? String ?? ""])
            XCTAssertEqual(object(try compareMembers(rosterJson: roster, membersJson: try members(a, c["members"], emails: false))),
                           c["expected"] as? NSDictionary)
        }
        for c in list("rosterRoles") {
            let roster = try XCTUnwrap(rosters[c["roster"] as? String ?? ""])
            let id = c["identity"] as? [Any] ?? []
            let identity = try who(a, id[0] as? String ?? "", legacy: id[1] as? Bool ?? false)
            XCTAssertEqual(try rosterMemberRole(rosterJson: roster, identityJson: identity), c["member"] as? String, "member \(c)")
            XCTAssertEqual(try rosterSignerRole(rosterJson: roster, signerJson: identity), c["signer"] as? String, "signer \(c)")
        }
    }

    func testKeyPinsReviewsEpochsAndAdmissions() throws {
        let a = try accounts()
        let key = try openKey(a, "wrappedKeyV2", epoch: 0, legacy: false)
        let second = try openKey(a, "secondKeyV2", epoch: 0, legacy: false)
        let rosters = try rosters(a, key: key)
        let pins = try text(v["keyPins"])
        // Made the same way: Bob verified with his signing key, Carol as legacy.
        var made = try pinSet(pinsJson: nil, identityJson: try who(a, "bob", legacy: false), email: "bob@example.com", verified: true, now: 1000)
        made = try pinSet(pinsJson: made, identityJson: try who(a, "carol", legacy: true), email: "carol@example.com", verified: false, now: 1000)
        XCTAssertEqual(object(made), object(pins))
        for c in list("pinChecks") {
            let id = c["identity"] as? [Any] ?? []
            XCTAssertEqual(try pinCheck(pinsJson: pins, identityJson: try who(a, id[0] as? String ?? "", legacy: id[1] as? Bool ?? false),
                                        email: c["email"] as? String), c["expected"] as? String, "\(c)")
        }
        for c in list("emails") {
            XCTAssertEqual(normalizeEmail(email: c["email"] as? String ?? ""), c["expected"] as? String, "\(c)")
        }
        // Shown in that form (an internationalized domain in punycode).
        XCTAssertEqual(SharingText.shownEmail("erin@B\u{00FC}cher.example"), "erin@xn--bcher-kva.example")
        for c in list("reviews") {
            let previous = str(c["previous"]).flatMap { rosters[$0] }
            let signer = try XCTUnwrap(a[c["signer"] as? String ?? ""]).signing
            let got = try rosterReview(vaultId: vaultId, previous: previous, signerJson: try signer.publicIdentityJson(),
                                       membersJson: try members(a, c["members"]), pinsJson: pins)
            XCTAssertEqual(object(got), c["expected"] as? NSDictionary, "review \(c["name"] ?? "")")
            let read = try XCTUnwrap(MemberReview.read(got))
            XCTAssertEqual(read.blocked, (c["expected"] as? Object)?["blocked"] as? Bool)
        }
        // The app lists the pins with fingerprints from the hashes alone.
        let people = KeyPinsReader.people(pins)
        XCTAssertEqual(people.map(\.email), ["bob@example.com", "carol@example.com"])
        XCTAssertEqual(people.first?.fingerprint, list("identities").first { $0["name"] as? String == "bob" }?["fingerprint"] as? String)
        XCTAssertEqual(people.map(\.verified), [true, false])
        let marked = try XCTUnwrap(try KeyPinsReader.markingVerified(pins, userId: people[1].userId, identityHash: people[1].identityHash))
        XCTAssertEqual(KeyPinsReader.people(marked).map(\.verified), [true, true])

        for c in list("epochChecks") {
            let pinned = try c["pinned"].flatMap { $0 is NSNull ? nil : try text($0) }
            XCTAssertEqual(try epochCheck(pinnedJson: pinned, currentJson: try text(c["current"])), c["expected"] as? String, "\(c)")
        }
        let withEpoch = try pinsSetEpoch(pinsJson: pins, vaultId: vaultId, currentJson: try key.epochPinJson(vaultId: vaultId, keyEpoch: 1), rosterVersion: 2)
        XCTAssertEqual(object(withEpoch), v["keyPinsWithEpoch"] as? NSDictionary)
        for c in list("pinsEpochChecks") {
            XCTAssertEqual(try pinsEpochCheck(pinsJson: withEpoch, vaultId: vaultId, currentJson: try text(c["current"]),
                                              rosterVersion: optNumber(c["rosterVersion"])), c["expected"] as? String, "\(c)")
        }
        let raised = try pinsSetEpoch(pinsJson: withEpoch, vaultId: vaultId, currentJson: try second.epochPinJson(vaultId: vaultId, keyEpoch: 2), rosterVersion: 3)
        XCTAssertEqual(object(raised), v["keyPinsRaised"] as? NSDictionary)
        let otherDevice = try pinsSetEpoch(pinsJson: nil, vaultId: vaultId, currentJson: try second.epochPinJson(vaultId: vaultId, keyEpoch: 2), rosterVersion: nil)
        XCTAssertEqual(object(try mergePins(baseJson: withEpoch, oursJson: otherDevice))?["epochs"] as? NSDictionary, v["mergedEpochs"] as? NSDictionary)
        let left = try pinsLeave(pinsJson: raised, vaultId: vaultId, rosterVersion: 3, now: 2000)
        XCTAssertEqual(object(left), v["keyPinsLeft"] as? NSDictionary)
        let grandfathered = try pinsGrandfather(pinsJson: pins, vaultIds: [vaultId], createdIdentity: true)
        XCTAssertEqual(object(grandfathered), v["keyPinsGrandfathered"] as? NSDictionary)
        let withheld = try pinsGrandfather(pinsJson: pins, vaultIds: [vaultId], createdIdentity: false)
        XCTAssertEqual(object(withheld), v["keyPinsWithheld"] as? NSDictionary)
        let unsigned = try pinsSetEpoch(pinsJson: grandfathered, vaultId: vaultId, currentJson: try key.epochPinJson(vaultId: vaultId, keyEpoch: 1),
                                        rosterVersion: nil)
        XCTAssertEqual(object(unsigned), v["keyPinsUnsigned"] as? NSDictionary)
        let v3 = try XCTUnwrap(rosters["v3"])
        let observed = try XCTUnwrap(SignedSharing.observe(withEpoch, vaultId: vaultId, kind: "sealed", epochPin: try key.epochPinJson(vaultId: vaultId, keyEpoch: 1),
                                                           rosterVersion: 3, rosterHash: try rosterHash(rosterJson: v3), signedShare: true, paused: false))
        let rosterMax = try XCTUnwrap(observed.pins)
        XCTAssertEqual(object(rosterMax), v["keyPinsRosterMax"] as? NSDictionary)
        // An account row marks the pin `own` (round 4).
        let ownObserved = try XCTUnwrap(SignedSharing.observe(nil, vaultId: vaultId, kind: "account", epochPin: try key.epochPinJson(vaultId: vaultId, keyEpoch: 1),
                                                              rosterVersion: nil, rosterHash: nil, signedShare: false, paused: false))
        let ownPins = try XCTUnwrap(ownObserved.pins)
        XCTAssertEqual(object(ownPins), v["keyPinsOwn"] as? NSDictionary)
        XCTAssertNotNil(KeyPinsReader.field(grandfathered, "grandfathered"))
        XCTAssertNil(KeyPinsReader.field(pins, "grandfathered"))
        XCTAssertTrue(KeyPinsReader.signedSince(withEpoch, vaultId))
        let sets: [String: String?] = ["none": nil, "withEpoch": withEpoch, "raised": raised, "left": left, "grandfathered": grandfathered,
                                       "withheld": withheld, "unsigned": unsigned, "rosterMax": rosterMax, "own": ownPins]
        for c in list("admissions") {
            let p = try XCTUnwrap(sets[c["pins"] as? String ?? ""], "\(c)")
            XCTAssertEqual(object(try pinsAdmit(pinsJson: p, observationJson: try text(c["observation"]))), c["expected"] as? NSDictionary, "admission \(c)")
            // The app's own observation (as the checks build it, `chain_hashes` included) gives the same verdict.
            if let o = c["observation"] as? Object, o["signed_share"] != nil, o["paused"] != nil {
                let built = SignedSharing.observation(vaultId: o["vault_id"] as? String ?? "", kind: o["key_kind"] as? String ?? "",
                                                      epochPin: o["key"].flatMap { $0 is NSNull ? nil : try? text($0) },
                                                      rosterVersion: optNumber(o["roster_version"]), rosterHash: o["roster_hash"] as? String,
                                                      chainHashes: o["chain_hashes"] as? [String: String],
                                                      signedShare: o["signed_share"] as? Bool ?? false, paused: o["paused"] as? Bool ?? false)
                outcome(c, "app admission \(c)", { try pinsAdmit(pinsJson: p, observationJson: built) },
                        same: { self.object($0) == ($1 as? NSDictionary) })
            }
        }
        XCTAssertGreaterThan(list("admissions").filter { ($0["observation"] as? Object)?["chain_hashes"] != nil }.count, 0)
        for c in list("accepts") {
            let p = try XCTUnwrap(sets[c["pins"] as? String ?? ""], "\(c)")
            outcome(c, "accept \(c)", { try pinsAccept(pinsJson: p, observationJson: try self.text(c["observation"])) },
                    same: { self.object($0) == ($1 as? NSDictionary) })
        }
        for c in list("merges") {
            XCTAssertEqual(object(try mergePins(baseJson: try text(c["base"]), oursJson: try text(c["ours"]))), c["expected"] as? NSDictionary,
                           "merge \(c["name"] ?? "")")
        }
        var step: String? = grandfathered
        for c in list("observations") {
            let got = try pinsObserve(pinsJson: step, observationJson: try text(c["observation"]))
            XCTAssertEqual(object(got), c["expected"] as? NSDictionary, "observation \(c)")
            step = try text(object(got)?["pins"])
        }
        for c in list("legacyWraps") {
            let p = try XCTUnwrap(sets[c["pins"] as? String ?? ""])
            XCTAssertEqual(try pinsLegacyWrapAllowed(pinsJson: p, vaultId: vaultId), c["expected"] as? Bool)
        }
        let own = v["ownIdentity"] as? Object ?? [:]
        XCTAssertEqual(try XCTUnwrap(a["alice"]).signing.identityHash(), own["hash"] as? String)
        let withOwn = try pinsSetOwnIdentity(pinsJson: pins, hash: own["hash"] as? String ?? "")
        XCTAssertEqual(object(withOwn), own["pins"] as? NSDictionary)
        for c in own["checks"] as? [Object] ?? [] {
            let p: String? = c["pins"] as? String == "withOwn" ? withOwn : nil
            XCTAssertEqual(try pinsCheckOwnIdentity(pinsJson: p, listed: c["listed"] as? String), c["expected"] as? String, "\(c)")
        }
        // Another own identity can't be remembered over the first.
        XCTAssertThrowsError(try pinsSetOwnIdentity(pinsJson: withOwn, hash: try XCTUnwrap(a["bob"]).signing.identityHash()))
        // Sealed with the account key as a version; another version is a rollback.
        let alice = try XCTUnwrap(a["alice"]).account
        let sealed = try alice.sealKeyPins(pinsJson: withEpoch, seq: 4)
        XCTAssertEqual(object(try alice.openKeyPins(sealed: sealed, seq: 4)), object(withEpoch).map { d -> NSDictionary in
            let m = d.mutableCopy() as! NSMutableDictionary
            m["version"] = 4
            return m
        })
        XCTAssertThrowsError(try alice.openKeyPins(sealed: sealed, seq: 3)) { XCTAssertEqual(self.code($0), "rollback") }
    }
}
