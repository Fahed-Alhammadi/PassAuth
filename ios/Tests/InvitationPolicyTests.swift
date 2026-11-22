import Foundation
import PassAuthKit
import XCTest

/// Vault invitations and account policies, the pure parts (`Shared/Invitations.swift`,
/// `Shared/Policies.swift`): reading `/sync` `invitations` and keeping them with the copy, the
/// invitation wording, policy reading and clamping, the vault timeout limit, export gating, the
/// violation notices and the two-step gate. Shared by the iOS tests and the macOS AutoFill tests.
final class InvitationPolicyTests: XCTestCase {
    private func answer(_ json: String) throws -> SyncResponse {
        try JSONDecoder().decode(SyncResponse.self, from: Data(json.utf8))
    }

    private let invitationJSON = #"{"vault_id":"V1","role":"write","wrapped_key":"sealed-1","meta":"meta-1","invited_by":{"id":"u2","email":"alex@example.com","name":"Alex Morgan","public_key":"pk"},"invited_at":1762000000}"#

    private func invitation(_ id: String = "V1", role: String = "write", name: String? = "Family", by: SyncInvitation.Sharer? = .init(id: "u2", email: "alex@example.com", name: "Alex Morgan", publicKey: "pk")) -> Invitation {
        Invitation(vaultId: id, role: role, name: name, invitedBy: by, invitedAt: 1_762_000_000)
    }

    // MARK: Reading

    func testInvitationsAreReadLeniently() throws {
        let raw = try JSON.parse(#"""
        [\#(invitationJSON),
         {"vault_id":"V1","role":"read","wrapped_key":"again","meta":"m"},
         {"vault_id":"V2","role":"admin","wrapped_key":"w2","meta":"m2","invited_by":null,"invited_at":1.5e9},
         {"vault_id":"V3","role":"captain","wrapped_key":"w3","meta":"m3","invited_by":{"email":"no-id@example.com"}},
         {"vault_id":"V4","role":"read","wrapped_key":"","meta":"m4"},
         {"vault_id":"V5","wrapped_key":"w5","meta":"m5"},
         {"role":"read","wrapped_key":"w6","meta":"m6"},
         "junk", 7, null]
        """#)
        let list = SyncInvitation.read(raw)
        XCTAssertEqual(list.map(\.vaultId), ["V1", "V2", "V3"], "malformed entries and a second V1 left out")
        XCTAssertEqual(list[0], SyncInvitation(vaultId: "V1", role: "write", wrappedKey: "sealed-1", meta: "meta-1",
                                               invitedBy: .init(id: "u2", email: "alex@example.com", name: "Alex Morgan", publicKey: "pk"),
                                               invitedAt: 1_762_000_000))
        XCTAssertNil(list[1].invitedBy)
        XCTAssertEqual(list[1].invitedAt, 1_500_000_000)
        XCTAssertEqual(list[2].role, "captain", "an unknown role is kept")
        XCTAssertNil(list[2].invitedBy, "a sharer without an id isn't one")
        XCTAssertNil(list[2].invitedAt)
        XCTAssertEqual(SyncInvitation.read(nil), [])
        XCTAssertEqual(SyncInvitation.read(.object([:])), [])
    }

    /// One malformed invitation never makes the whole answer unreadable.
    func testAMalformedInvitationDoesntBreakTheSync() throws {
        let r = try answer(#"{"revision":3,"vaults":[],"items":[],"invitations":[{"vault_id":5},\#(invitationJSON)]}"#)
        let s = try XCTUnwrap(SyncMerge.apply(r, to: nil))
        XCTAssertEqual(s.invitations.map(\.vaultId), ["V1"])
        let odd = try answer(#"{"revision":3,"vaults":[],"items":[],"invitations":"nope"}"#)
        XCTAssertEqual(try XCTUnwrap(SyncMerge.apply(odd, to: nil)).invitations, [])
    }

    // MARK: Kept with the copy

    func testEveryAnswerReplacesTheInvitations() throws {
        let full = try XCTUnwrap(SyncMerge.apply(try answer(#"{"revision":3,"cursor":"c1","vaults":[],"items":[],"invitations":[\#(invitationJSON)]}"#), to: nil))
        XCTAssertEqual(full.invitations.map(\.vaultId), ["V1"])
        // A delta lists them in full too: the new list replaces the old one…
        let delta = try XCTUnwrap(SyncMerge.apply(try answer(#"{"delta":true,"revision":4,"cursor":"c2","vaults":[],"items":[],"deleted":[],"reset":[],"invitations":[{"vault_id":"V2","role":"read","wrapped_key":"w","meta":"m"}]}"#), to: full))
        XCTAssertEqual(delta.invitations.map(\.vaultId), ["V2"])
        // … an empty one (accepted, declined or cancelled) empties it…
        let none = try XCTUnwrap(SyncMerge.apply(try answer(#"{"delta":true,"revision":5,"cursor":"c3","vaults":[],"items":[],"deleted":[],"reset":[],"invitations":[]}"#), to: delta))
        XCTAssertEqual(none.invitations, [])
        // … and a server without them sends none.
        let older = try XCTUnwrap(SyncMerge.apply(try answer(#"{"revision":6,"vaults":[],"items":[]}"#), to: delta))
        XCTAssertEqual(older.invitations, [])
    }

    func testLocalChangesKeepTheInvitations() throws {
        let base = try XCTUnwrap(SyncMerge.apply(try answer(#"{"revision":3,"cursor":"c1","vaults":[{"id":"A","meta":"m","role":"owner","wrapped_key":"w","key_kind":"account","key_epoch":0,"seq":1}],"items":[],"invitations":[\#(invitationJSON)]}"#), to: nil))
        let next = try XCTUnwrap(SyncMerge.applyLocal(.put(SyncItem(id: "1", vaultId: "A", itemKey: "k", data: "d", revision: 9)), vaultId: "A", vaultSeq: 2, to: base))
        XCTAssertEqual(next.invitations, base.invitations)
    }

    func testCopyKeepsInvitationsAndOlderCopiesHaveNone() throws {
        let s = try XCTUnwrap(SyncMerge.apply(try answer(#"{"revision":3,"cursor":"c1","vaults":[],"items":[],"invitations":[\#(invitationJSON)]}"#), to: nil))
        let again = try XCTUnwrap(SyncSnapshot.decode(try s.encoded()))
        XCTAssertEqual(again, s)
        XCTAssertEqual(try JSONDecoder().decode(SyncSnapshot.self, from: try s.encoded()), s)
        // A copy stored before invitations existed.
        let old = Data(#"{"revision":3,"cursor":"c1","vaults":[],"items":[]}"#.utf8)
        XCTAssertEqual(SyncSnapshot.decode(old)?.invitations, [])
        XCTAssertEqual(try JSONDecoder().decode(SyncSnapshot.self, from: old).invitations, [])
    }

    // MARK: Opening

    func testNamesAreReadOnceAndUnopenableOnesHaveNone() throws {
        let list = SyncInvitation.read(try JSON.parse(#"[\#(invitationJSON),{"vault_id":"V2","role":"read","wrapped_key":"bad","meta":"m2"}]"#))
        var opened: [String] = []
        let first = Invitation.open(list, previous: [:]) { inv in
            opened.append(inv.vaultId)
            if inv.wrappedKey == "bad" { throw UserError("can't open") }
            return Invitation.name(fromMeta: #"{"name":"Family"}"#)
        }
        XCTAssertEqual(first.invitations.map(\.name), ["Family", nil])
        XCTAssertEqual(first.invitations[0].invitedBy?.email, "alex@example.com")
        XCTAssertEqual(opened, ["V1", "V2"])
        // The same sealed keys and names: nothing is opened again (also not the failed one).
        opened = []
        let second = Invitation.open(list, previous: first.names) { inv in
            opened.append(inv.vaultId)
            return "other"
        }
        XCTAssertEqual(second.invitations.map(\.name), ["Family", nil])
        XCTAssertEqual(opened, [])
        // A new sealed key (the vault's key was replaced) is opened again.
        var changed = list
        changed[0].wrappedKey = "sealed-2"
        let third = Invitation.open(changed, previous: second.names) { _ in "Renamed" }
        XCTAssertEqual(third.invitations.map(\.name), ["Renamed", nil])
        XCTAssertEqual(third.names.count, 2, "only the names shown now are kept")
    }

    func testNameFromMeta() {
        XCTAssertEqual(Invitation.name(fromMeta: #"{"name":"Family"}"#), "Family")
        XCTAssertEqual(Invitation.name(fromMeta: #"{"name":"  "}"#), "Shared vault")
        XCTAssertEqual(Invitation.name(fromMeta: #"{}"#), "Shared vault")
        XCTAssertNil(Invitation.name(fromMeta: "not json"))
        XCTAssertNil(Invitation.name(fromMeta: "[1]"))
    }

    // MARK: Wording

    func testInvitationWording() {
        let inv = invitation()
        XCTAssertEqual(InvitationText.sharer(inv), "Alex Morgan (alex@example.com)")
        XCTAssertEqual(InvitationText.sharerShort(inv), "Alex Morgan")
        XCTAssertEqual(InvitationText.sharer(invitation(by: nil)), "Someone whose account was deleted")
        XCTAssertEqual(InvitationText.sharer(invitation(by: .init(id: "u", email: "e@x.test"))), "e@x.test")
        XCTAssertEqual(InvitationText.sharer(invitation(by: .init(id: "u", name: " Sam "))), "Sam")
        XCTAssertEqual(InvitationText.sharer(invitation(by: .init(id: "u"))), "Someone on this server")
        XCTAssertEqual(InvitationText.sharerShort(invitation(by: .init(id: "u", email: "e@x.test"))), "e@x.test")
        XCTAssertEqual(InvitationText.sharerShort(invitation(by: nil)), "the person who shared it")

        XCTAssertEqual(["owner", "admin", "write", "read", "captain"].map(InvitationText.role), ["Owner", "Admin", "Can edit", "Can view", "captain"])
        XCTAssertEqual(InvitationText.acceptBody(invitation(role: "write")),
                       "The vault and its items appear in all your apps. You'll be able to view and edit its items. The people who manage it can add and change items in it.")
        XCTAssertEqual(InvitationText.acceptBody(invitation(role: "owner")),
                       "The vault and its items appear in all your apps. The people who manage it can add and change items in it.")
        XCTAssertEqual(InvitationText.roleSentence("read"), "You'll be able to view its items.")
        XCTAssertEqual(InvitationText.roleSentence("admin"), "You'll be able to edit its items and share the vault.")

        // Client review F2: the fingerprint is what the server lists, never proof the
        // invitation is genuine (its sealed key is anonymous).
        XCTAssertEqual(InvitationText.fingerprintLabel(inv), "Fingerprint your server lists for alex@example.com")
        XCTAssertEqual(InvitationText.fingerprintLabel(invitation(by: .init(id: "u", name: "Sam"))), "Fingerprint your server lists for Sam")
        XCTAssertEqual(InvitationText.fingerprintLabel(invitation(by: .init(id: "u"))), "Fingerprint your server lists for the person who shared it")
        XCTAssertEqual(InvitationText.checkHint(inv), "Accept only invitations you expected.")
        XCTAssertEqual(InvitationText.cantOpen(inv),
                       "Your account's keys can't open this invitation, so PassAuth can't show the vault's name. Decline it, then ask Alex Morgan to share the vault again.")
        XCTAssertEqual(InvitationText.noFingerprint(invitation(by: nil)),
                       "The account that shared this vault no longer exists. Accept only invitations you expected.")
        XCTAssertEqual(InvitationText.noFingerprint(inv),
                       "PassAuth can't show the fingerprint your server lists for alex@example.com. Accept only invitations you expected.")
        XCTAssertEqual(InvitationText.acceptTitle("Family"), "Accept \"Family\"?")
        XCTAssertEqual(InvitationText.acceptCheck(inv), "Accept only invitations you expected.")
        XCTAssertEqual(InvitationText.intro, "A vault shared with you appears in your apps only after you accept it.")
        for text in [InvitationText.intro, InvitationText.checkHint(inv), InvitationText.acceptCheck(inv), InvitationText.noFingerprint(inv)] {
            XCTAssertFalse(text.contains("matches"), "never presented as a check")
        }
        // The names the server lists are shown without control or format characters.
        let spoofed = invitation(by: .init(id: "u", email: "boss@example.com\u{202E}moc.live", name: "The\u{200B} Boss\n"))
        XCTAssertEqual(InvitationText.sharer(spoofed), "The Boss (boss@example.commoc.live)")
        XCTAssertEqual(InvitationText.joined("Family"), "You joined \"Family\".")
    }

    func testVaultListNotice() {
        XCTAssertNil(InvitationText.notice([]))
        XCTAssertEqual(InvitationText.notice([invitation()]),
                       "Alex Morgan invited you to the shared vault \"Family\". Nothing from it reaches your apps until you accept.")
        XCTAssertEqual(InvitationText.notice([invitation(name: nil, by: nil)]),
                       "Someone invited you to a shared vault. Nothing from it reaches your apps until you accept.")
        XCTAssertEqual(InvitationText.notice([invitation("V1"), invitation("V2")]),
                       "You have 2 invitations to shared vaults. Nothing from them reaches your apps until you accept.")
        XCTAssertEqual(InvitationText.noticeAction(1), "See the invitation")
        XCTAssertEqual(InvitationText.noticeAction(2), "See the invitations")
        XCTAssertEqual(InvitationText.key([invitation("V2"), invitation("V1")]), "V1,V2")
        XCTAssertEqual(InvitationText.key([]), "")
    }

    // MARK: Policies

    func testPoliciesReadWithDefaultsAndClamps() throws {
        XCTAssertEqual(Policies(json: nil), Policies())
        XCTAssertEqual(Policies(json: "nope"), Policies())
        let p = Policies(json: try JSON.parse(#"{"require_two_step":true,"require_secret_key":true,"min_kdf_memory_mib":256,"min_kdf_iterations":4,"master_password_min_length":14,"max_vault_timeout_minutes":45,"disable_export":true}"#))
        XCTAssertTrue(p.requireTwoStep)
        XCTAssertTrue(p.requireSecretKey)
        XCTAssertEqual(p.minKdfMemoryMib, 256)
        XCTAssertEqual(p.minKdfIterations, 4)
        XCTAssertEqual(p.masterPasswordMinLength, 14)
        XCTAssertEqual(p.maxVaultTimeoutMinutes, 45)
        XCTAssertTrue(p.disableExport)
        // Out of range → clamped; not a whole number → default; only `true` turns a switch on.
        let odd = Policies(json: try JSON.parse(#"{"require_two_step":"yes","require_secret_key":"true","min_kdf_memory_mib":4096,"min_kdf_iterations":1,"master_password_min_length":4,"max_vault_timeout_minutes":-5,"disable_export":null}"#))
        XCTAssertEqual(odd, Policies(json: try JSON.parse(#"{"min_kdf_memory_mib":1024}"#)))
        XCTAssertEqual(odd.minKdfMemoryMib, 1024)
        XCTAssertEqual(odd.minKdfIterations, 3)
        XCTAssertEqual(odd.masterPasswordMinLength, 10)
        XCTAssertEqual(odd.maxVaultTimeoutMinutes, 0)
        XCTAssertFalse(odd.requireTwoStep || odd.requireSecretKey || odd.disableExport)
        XCTAssertEqual(Policies(json: try JSON.parse(#"{"master_password_min_length":12.5,"max_vault_timeout_minutes":60.0,"min_kdf_iterations":"5"}"#)),
                       Policies(json: try JSON.parse(#"{"max_vault_timeout_minutes":60}"#)))
        XCTAssertEqual(Policies(json: try JSON.parse(#"{"max_vault_timeout_minutes":999999}"#)).maxVaultTimeoutMinutes, 43_200)
        // Stored with the account: round trip, and anything missing is a default.
        XCTAssertEqual(try JSONDecoder().decode(Policies.self, from: try JSONEncoder().encode(p)), p)
        XCTAssertEqual(try JSONDecoder().decode(Policies.self, from: Data("{}".utf8)), Policies())
    }

    func testPublicConfigReadsThePolicies() throws {
        let with = try XCTUnwrap(PublicConfig(json: try JSON.parse(#"{"name":"PassAuth","features":["policies","forget_device"],"signups_allowed":false,"policies":{"disable_export":true}}"#)))
        XCTAssertTrue(with.policies.disableExport)
        XCTAssertEqual(with.signupsAllowed, false)
        XCTAssertEqual(with.features, ["policies", "forget_device"])
        // A server that sets none: the defaults, which change nothing.
        let without = try XCTUnwrap(PublicConfig(json: try JSON.parse(#"{"name":"PassAuth","features":["delta_sync"]}"#)))
        XCTAssertEqual(without.policies, Policies())
        XCTAssertNil(without.signupsAllowed)
        XCTAssertNil(PublicConfig(json: "text"))
    }

    func testPasswordLengthExportAndKdf() {
        var p = Policies()
        XCTAssertEqual(PolicyRules.minPasswordLength(p), 10)
        p.masterPasswordMinLength = 16
        XCTAssertEqual(PolicyRules.minPasswordLength(p), 16)
        p.masterPasswordMinLength = 6
        XCTAssertEqual(PolicyRules.minPasswordLength(p), 10, "never below the apps' own")
        XCTAssertTrue(PolicyRules.exportAllowed(p))
        p.disableExport = true
        XCTAssertFalse(PolicyRules.exportAllowed(p))
        // New keys follow the server's minimums: from the config read right before, else the
        // policies kept with the account; none (the core's defaults) when neither is known.
        p.minKdfMemoryMib = 256
        p.minKdfIterations = 4
        var config = PublicConfig(features: ["policies"], policies: p)
        XCTAssertEqual(PolicyRules.kdfMinimums(config), KdfMinimums(memoryMib: 256, iterations: 4))
        XCTAssertEqual(PolicyRules.kdfMinimums(config, stored: Policies()), KdfMinimums(memoryMib: 256, iterations: 4), "the fresh config wins")
        config.policies = Policies()
        XCTAssertEqual(PolicyRules.kdfMinimums(config), KdfMinimums(Policies()), "no policy set: the server's defaults, below the core's own")
        XCTAssertEqual(PolicyRules.kdfMinimums(nil, stored: p), KdfMinimums(memoryMib: 256, iterations: 4), "offline: the kept policy")
        XCTAssertEqual(PolicyRules.kdfMinimums(nil), KdfMinimums())
        XCTAssertEqual(KdfMinimums(Policies()), KdfMinimums(memoryMib: 64, iterations: 3), "the floors: the core then uses 128 MiB and 3 passes")
        // A `kdf` fix may keep the same password; otherwise the same password is refused.
        let same: (Bool) -> AccountSecurityLogic.PasswordProblem? = { allow in
            AccountSecurityLogic.passwordProblem(current: "same password 123", new: "same password 123", confirm: "same password 123", secretKeyChange: .keep,
                                                 weakAccepted: false, bits: { _ in 100 }, allowSame: allow)
        }
        XCTAssertEqual(same(false), .sameAsCurrent)
        XCTAssertNil(same(true))
        // The change-password check uses the server's minimum.
        let bits: (String) -> Double = { _ in 100 }
        XCTAssertEqual(AccountSecurityLogic.passwordProblem(current: "c", new: "twelve-chars", confirm: "twelve-chars", secretKeyChange: .keep,
                                                            weakAccepted: false, bits: bits, minLength: 14), .tooShort)
        XCTAssertNil(AccountSecurityLogic.passwordProblem(current: "c", new: "fourteen-chars", confirm: "fourteen-chars", secretKeyChange: .keep,
                                                          weakAccepted: false, bits: bits, minLength: 14))
        XCTAssertEqual(AccountSecurityLogic.PasswordProblem.tooShort.message(minLength: 14), "Use at least 14 characters for your new master password.")
        XCTAssertEqual(AccountSecurityLogic.PasswordProblem.tooShort.message, "Use at least 10 characters for your new master password.")
    }

    func testVaultTimeoutLimit() {
        XCTAssertEqual(PolicyRules.timeoutOptions(max: 0), VaultTimeout.allCases)
        XCTAssertEqual(PolicyRules.timeoutOptions(max: 45), [.immediately, .min1, .min5, .min15, .min30])
        XCTAssertEqual(PolicyRules.timeoutOptions(max: 1), [.immediately, .min1])
        XCTAssertEqual(PolicyRules.timeoutOptions(max: 240), [.immediately, .min1, .min5, .min15, .min30, .hour1, .hour4])
        XCTAssertEqual(PolicyRules.timeoutOptions(max: 43_200), [.immediately, .min1, .min5, .min15, .min30, .hour1, .hour4],
                       "no time limit (restart, never) is above every limit")
        XCTAssertEqual(PolicyRules.clampTimeout(.never, max: 45), .min30)
        XCTAssertEqual(PolicyRules.clampTimeout(.restart, max: 240), .hour4)
        XCTAssertEqual(PolicyRules.clampTimeout(.hour1, max: 59), .min30)
        XCTAssertEqual(PolicyRules.clampTimeout(.min15, max: 45), .min15, "within: kept")
        XCTAssertEqual(PolicyRules.clampTimeout(.never, max: 0), .never, "no limit")
        XCTAssertEqual(PolicyRules.clampTimeout(.immediately, max: 1), .immediately)
        XCTAssertEqual(PolicyRules.strictestLimit([0, 60, 15, 0]), 15)
        XCTAssertEqual(PolicyRules.strictestLimit([0, 0]), 0)
        XCTAssertEqual(PolicyRules.strictestLimit([]), 0)
        XCTAssertEqual([1, 45, 60, 90, 240, 1440, 43_200].map(PolicyRules.minutesLabel),
                       ["1 minute", "45 minutes", "1 hour", "90 minutes", "4 hours", "1 day", "30 days"])
        XCTAssertEqual(PolicyRules.timeoutLimitNote(45), "Your server allows at most 45 minutes before the vault locks.")
        XCTAssertEqual(PolicyRules.timeoutLoweredNote(.min30), "Your previous choice was longer, so it was lowered to 30 minutes.")
    }

    /// The limit is the strictest of the signed-in accounts' servers.
    func testStoredTimeoutLimit() {
        var s = Stored()
        var a = AccountData(server: "https://a.test", email: "a@x.test")
        a.policies = Policies(json: ["max_vault_timeout_minutes": 60])
        var b = AccountData(server: "https://b.test", email: "b@x.test")
        b.policies = Policies(json: ["max_vault_timeout_minutes": 15])
        let c = AccountData(server: "https://c.test", email: "c@x.test")
        s.file.accounts = ["a": a, "b": b, "c": c]
        s.secrets.tokens = ["a": Tokens(access: "x", refresh: "y"), "c": Tokens(access: "x", refresh: "y")]
        XCTAssertEqual(s.timeoutLimit, 60, "b is signed out")
        s.secrets.tokens["b"] = Tokens(access: "x", refresh: "y")
        XCTAssertEqual(s.timeoutLimit, 15)
        s.secrets.tokens = [:]
        XCTAssertEqual(s.timeoutLimit, 0)
    }

    /// Website icons: the user's setting and the server's icon service together (the web
    /// vault's `siteIconsShown`); API 2 servers list `icons` only while the service is on.
    func testSiteIconsFollowTheSettingAndTheServer() throws {
        XCTAssertFalse(SiteIcons.shown(wanted: false, api: 2, features: ["icons"]))
        XCTAssertFalse(SiteIcons.shown(wanted: false, api: nil, features: nil))
        XCTAssertTrue(SiteIcons.shown(wanted: true, api: nil, features: nil), "config not asked yet: the setting decides")
        XCTAssertTrue(SiteIcons.shown(wanted: true, api: nil, features: []), "kept before the app stored `api`: the setting decides")
        XCTAssertTrue(SiteIcons.shown(wanted: true, api: 2, features: ["delta_sync", "icons"]))
        XCTAssertFalse(SiteIcons.shown(wanted: true, api: 2, features: ["delta_sync"]))
        XCTAssertFalse(SiteIcons.shown(wanted: true, api: 3, features: []))
        // The config's API version: a whole number, else none.
        XCTAssertEqual(PublicConfig(json: try JSON.parse(#"{"api":2,"features":["icons"]}"#))?.api, 2)
        XCTAssertEqual(PublicConfig(json: try JSON.parse(#"{"api":2.0}"#))?.api, 2)
        XCTAssertNil(PublicConfig(json: try JSON.parse(#"{"features":[]}"#))?.api)
        XCTAssertNil(PublicConfig(json: try JSON.parse(#"{"api":"2"}"#))?.api)
        XCTAssertNil(PublicConfig(json: try JSON.parse(#"{"api":2.5}"#))?.api)
        // Kept with the account; a file written before it existed still reads.
        let old = try JSONDecoder().decode(AccountData.self, from: Data(#"{"server":"https://a.test","email":"x@a.test","name":"","lastSync":0,"biometric":false}"#.utf8))
        XCTAssertNil(old.api)
        var a = old
        a.api = 2
        XCTAssertEqual(try JSONDecoder().decode(AccountData.self, from: try JSONEncoder().encode(a)).api, 2)
    }

    func testViolationsAndNotices() throws {
        XCTAssertEqual(PolicyRules.readViolations(try JSON.parse(#"["kdf","bogus","two_step","kdf","secret_key"]"#)), [.twoStep, .secretKey, .kdf])
        XCTAssertEqual(PolicyRules.readViolations(nil), [])
        XCTAssertEqual(PolicyRules.readViolations("two_step"), [])
        let notices = PolicyRules.notices([.twoStep, .secretKey, .kdf], Policies())
        XCTAssertEqual(notices.map(\.text), [
            "Your server requires two-step login.",
            "Your server asks you to turn on a Secret Key.",
            "Your server asks you to update your account's encryption settings. Change your master password to update them. You can keep the same password.",
        ])
        XCTAssertEqual(notices.map(\.action), [.setUpTwoStep, .turnOnSecretKey, .changePassword])
        XCTAssertEqual(notices.compactMap(\.action?.label), ["Set up two-step login", "Turn on a Secret Key", "Change master password"])
        // Any minimum the server can set, the core can create keys for (createAccountWithKdf / rewrapWithKdf).
        let strong = PolicyRules.notices([.kdf], Policies(json: ["min_kdf_memory_mib": 512]))
        XCTAssertEqual(strong.first?.action, .changePassword)
        XCTAssertEqual(PolicyRules.violationsKey([.twoStep, .kdf]), "two_step,kdf")
        XCTAssertEqual(PolicyRules.violationsKey([]), "")
    }

    func testTwoStepGate() {
        XCTAssertTrue(TwoStepGate.isRequired(status: 403, code: "two_step_required"))
        XCTAssertFalse(TwoStepGate.isRequired(status: 403, code: "forbidden"))
        XCTAssertFalse(TwoStepGate.isRequired(status: 400, code: "two_step_required"))
        XCTAssertEqual(TwoStepGate.afterSetup(keysInMemory: true), .sync)
        XCTAssertEqual(TwoStepGate.afterSetup(keysInMemory: false), .unlock)
        XCTAssertEqual(TwoStepGate.intro(email: "a@x.test"),
                       "Set up a second step for a@x.test to open your vault. It's asked for after your master password when you sign in on a new device, so a stolen password isn't enough.")
    }

    func testPolicyErrorsInPlainWords() {
        XCTAssertEqual(errorMessage(ApiError(status: 400, code: "secret_key_required", message: "this server requires a Secret Key")),
                       "Your server requires a Secret Key. Turn on \"Use a Secret Key\" and try again.")
        XCTAssertEqual(errorMessage(ApiError(status: 400, code: "kdf_too_weak", message: "stronger")),
                       "Your server's encryption settings have changed. Try again.")
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "two_step_required", message: "turn it on")),
                       "Your server requires two-step login. Set it up to continue.")
        // The app's own "enter your Secret Key" message is unchanged.
        XCTAssertEqual(errorMessage(UserError(secretKeyRequiredMessage)), "This account uses a Secret Key. Enter it from your Emergency Kit.")
    }

    func testSettingsKeepTheLoweredMark() throws {
        var s = Settings()
        XCTAssertFalse(s.vaultTimeoutLowered)
        s.vaultTimeoutLowered = true
        XCTAssertTrue(try JSONDecoder().decode(Settings.self, from: try JSONEncoder().encode(s)).vaultTimeoutLowered)
        XCTAssertFalse(try JSONDecoder().decode(Settings.self, from: Data("{}".utf8)).vaultTimeoutLowered)
    }
}
