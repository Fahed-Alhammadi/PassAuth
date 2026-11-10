import PassAuthCore
import PassAuthKit
import XCTest

/// AutoFill saving logins (`SaveLogic`, `VaultRepository.saveLogin`'s plan) and password
/// generation (`PasswordRules`, `PasswordGeneration`).
final class SaveGenerateTests: XCTestCase {
    private func entry(_ id: String, user: String, password: String, url: String, match: UrlMatch = .default, vault: String = "v1") -> Entry {
        let item = Item(name: id, login: Login(username: user, password: password, urls: [LoginUrl(url: url, match: match)]))
        return Entry(id: id, item: item, vaultId: vault, revision: 1, enc: EncryptedItem(id: id, vaultId: vault, key: "", data: ""), deletedAt: nil)
    }

    private func vault(_ entries: [Entry]) -> VaultData {
        var v = VaultData()
        v.entries = entries
        v.vaults = [
            VaultInfo(id: "v1", name: "Personal", role: .owner),
            VaultInfo(id: "ro", name: "Shared", role: .read, keyKind: "sealed"),
            // A vault somebody shared with write access (nobody has to accept a share).
            VaultInfo(id: "team", name: "Team", role: .write, keyKind: "sealed"),
        ]
        return v
    }

    private func plan(_ v: VaultData, page: String = "https://login.example.com/signup", user: String, password: String) -> SaveLogic.Plan {
        SaveLogic.plan(page: page, username: user, password: password, vault: v, defaultMatch: .domain)
    }

    // MARK: Save: offer or not

    func testSaveBlocked() {
        var s = Settings()
        XCTAssertNil(SaveLogic.blocked(page: "https://www.shop.co.uk/register", password: "pw", settings: s))
        XCTAssertNil(SaveLogic.blocked(page: "https://pass.example.org/login", password: "pw", settings: s), "the server's own web vault is saved like any site")
        XCTAssertEqual(SaveLogic.blocked(page: nil, password: "pw", settings: s), .notWebsite, "apps without a domain")
        XCTAssertEqual(SaveLogic.blocked(page: "https://example.com/", password: "", settings: s), .noPassword)
        s.neverSave = ["shop.co.uk"]
        XCTAssertEqual(SaveLogic.blocked(page: "https://accounts.shop.co.uk/x", password: "pw", settings: s), .neverSave, "keyed by base domain")
        XCTAssertNil(SaveLogic.blocked(page: "https://example.com/", password: "pw", settings: s))
        s.askToSave = false
        XCTAssertEqual(SaveLogic.blocked(page: "https://example.com/", password: "pw", settings: s), .askToSaveOff)
    }

    func testNeverSaveKey() {
        XCTAssertEqual(SaveLogic.neverSaveKey("https://accounts.shop.co.uk/x"), "shop.co.uk")
        XCTAssertEqual(SaveLogic.neverSaveKey("https://www.example.com/"), "example.com")
        XCTAssertEqual(SaveLogic.neverSaveKey("http://localhost:8099/ios-signup.html"), "localhost")
        XCTAssertNil(SaveLogic.neverSaveKey("not a url"))
    }

    func testSettingsKeepNeverSaveAndGenerator() throws {
        var s = Settings()
        s.neverSave = ["example.com"]
        s.generator.length = 32
        s.generator.passphrase = true
        let back = try JSONDecoder().decode(Settings.self, from: JSONEncoder().encode(s))
        XCTAssertEqual(back, s)
        // Older files without the generator, and out-of-range values.
        let old = try JSONDecoder().decode(Settings.self, from: Data(#"{"askToSave":false,"generator":{"length":3,"words":99}}"#.utf8))
        XCTAssertFalse(old.askToSave)
        XCTAssertEqual(old.generator.length, 8)
        XCTAssertEqual(old.generator.words, 20)
        XCTAssertTrue(old.generator.symbols)
    }

    // MARK: Save: what changes

    func testPlanNewLogin() {
        let v = vault([entry("other", user: "alice", password: "a", url: "https://example.org")])
        guard case .create = plan(v, user: "alice", password: "new") else { return XCTFail("new login") }
        let item = SaveLogic.newItem(page: "https://www.example.com/signup?step=2", username: " alice ", password: "new")
        XCTAssertEqual(item.name, "example.com")
        XCTAssertEqual(item.login?.username, "alice")
        XCTAssertEqual(item.login?.password, "new")
        XCTAssertEqual(item.login?.urls, [LoginUrl(url: "https://www.example.com", match: .default)])
        // An app's associated domain arrives as https://<domain>/.
        XCTAssertEqual(SaveLogic.newItem(page: "https://example.com/", username: "", password: "x").login?.urls.first?.url, "https://example.com")
    }

    func testPlanUpdateSameSiteAndUser() {
        let v = vault([
            entry("bob", user: "bob", password: "b", url: "https://example.com"),
            entry("alice", user: "Alice", password: "old", url: "https://www.example.com/login"),
        ])
        guard case .update(let e, let why) = plan(v, user: "alice", password: "new") else { return XCTFail("update") }
        XCTAssertEqual(e.id, "alice", "same base domain, user name case-insensitive")
        XCTAssertEqual(why, .same)
        let item = SaveLogic.updatedItem(e, username: " alice ", password: "new")
        XCTAssertEqual(item.login?.password, "new")
        XCTAssertEqual(item.login?.username, "alice", "the user name as typed (trimmed)")
        XCTAssertEqual(item.passwordHistory, [], "the repository's updateItem adds the old password to the history")
        guard case .unchanged = plan(v, user: "alice", password: "old") else { return XCTFail("same password: nothing to do") }
        guard case .create = plan(v, user: "carol", password: "x") else { return XCTFail("other user: new login") }
    }

    /// Rule 1: only the user name was saved (no password yet) → that login gets the password.
    func testPlanOnlyUserNameSaved() {
        let v = vault([entry("a", user: "alice", password: "", url: "https://example.com")])
        guard case .update(let e, _) = plan(v, user: "Alice", password: "new") else { return XCTFail("update, not a second login") }
        XCTAssertEqual(e.id, "a")
        let item = SaveLogic.updatedItem(e, username: "Alice", password: "new")
        XCTAssertEqual(item.login?.username, "Alice")
        XCTAssertEqual(item.login?.password, "new")
        XCTAssertEqual(item.login?.urls, e.item.login?.urls)
        XCTAssertEqual(item.name, "a")
    }

    /// Rule 2: only a password was saved (no user name) → that login gets the user name too.
    func testPlanOnlyPasswordSaved() {
        let v = vault([
            entry("bob", user: "bob", password: "b", url: "https://example.com"),
            entry("bare", user: " ", password: "old", url: "https://example.com"),
        ])
        guard case .update(let e, let why) = plan(v, user: "alice", password: "new") else { return XCTFail("update the login without a user name") }
        XCTAssertEqual(e.id, "bare")
        XCTAssertEqual(why, .blank)
        let item = SaveLogic.updatedItem(e, username: " alice ", password: "new")
        XCTAssertEqual(item.login?.username, "alice")
        XCTAssertEqual(item.login?.password, "new")
        // The same password: still an update, the user name gets filled in.
        let p = plan(v, user: "alice", password: "old")
        guard case .update(let same, _) = p else { return XCTFail("update even with the saved password") }
        XCTAssertEqual(same.id, "bare")
        XCTAssertTrue(p.isChange)
        XCTAssertEqual(SaveLogic.updatedItem(same, username: "alice", password: "old").login?.username, "alice")
    }

    /// Rule 2 with several logins that have no user name: the one with the typed password, else the first.
    func testPlanSeveralWithoutUserName() {
        let v = vault([
            entry("one", user: "", password: "p1", url: "https://example.com"),
            entry("two", user: "", password: "p2", url: "https://example.com"),
        ])
        guard case .update(let match, _) = plan(v, user: "alice", password: "p2") else { return XCTFail("update") }
        XCTAssertEqual(match.id, "two", "the one that already has this password")
        guard case .update(let first, _) = plan(v, user: "alice", password: "p3") else { return XCTFail("update") }
        XCTAssertEqual(first.id, "one", "else the first")
        // A view-only login without a user name isn't a target: new login.
        let ro = vault([entry("r", user: "", password: "p1", url: "https://example.com", vault: "ro")])
        guard case .create = plan(ro, user: "alice", password: "p1") else { return XCTFail("read-only: new login") }
        // The editable one wins over a view-only one, even when that has the password.
        let both = vault([entry("r", user: "", password: "p2", url: "https://example.com", vault: "ro"), entry("w", user: "", password: "p1", url: "https://example.com")])
        guard case .update(let w, _) = plan(both, user: "alice", password: "p2") else { return XCTFail("update") }
        XCTAssertEqual(w.id, "w")
    }

    /// No user name typed, and logins without a user name exist (rule 1 with an empty user name).
    func testPlanNoUserNameTypedBareLogins() {
        let v = vault([
            entry("alice", user: "alice", password: "a", url: "https://example.com"),
            entry("bare", user: "", password: "old", url: "https://example.com"),
        ])
        guard case .update(let e, _) = plan(v, user: "  ", password: "new") else { return XCTFail("update the password-only login") }
        XCTAssertEqual(e.id, "bare")
        XCTAssertEqual(SaveLogic.updatedItem(e, username: "", password: "new").login?.username, "")
        guard case .unchanged(let u) = plan(v, user: "", password: "old") else { return XCTFail("already saved") }
        XCTAssertEqual(u.id, "bare")
        // "alice" has this password, but the password-only login is the one that decides.
        guard case .update = plan(v, user: "", password: "a") else { return XCTFail("update the password-only login") }
        // A view-only login without a user name in a shared vault: not "the same login" (new login);
        // its password still counts as saved.
        let ro = vault([entry("r", user: "", password: "old", url: "https://example.com", vault: "ro")])
        guard case .create = plan(ro, user: "", password: "new") else { return XCTFail("shared, no user name: new login") }
        guard case .unchanged = plan(ro, user: "", password: "old") else { return XCTFail("already saved") }
    }

    /// Rule 3: no user name typed and every login for the site has one.
    func testPlanNoUserNameTyped() {
        let one = vault([entry("alice", user: "alice", password: "old", url: "https://example.com")])
        guard case .update(let e, let why) = plan(one, user: "", password: "new") else { return XCTFail("the only login: update") }
        XCTAssertEqual(e.id, "alice")
        XCTAssertEqual(why, .only, "the rule that is never applied without the sheet")
        let item = SaveLogic.updatedItem(e, username: "", password: "new")
        XCTAssertEqual(item.login?.username, "alice", "user name kept")
        XCTAssertEqual(item.login?.password, "new")
        guard case .unchanged = plan(one, user: "", password: "old") else { return XCTFail("password already saved") }

        let two = vault([
            entry("alice", user: "alice", password: "a", url: "https://example.com"),
            entry("bob", user: "bob", password: "b", url: "https://example.com"),
        ])
        guard case .create = plan(two, user: "", password: "new") else { return XCTFail("two logins: can't tell which, new login") }
        guard case .unchanged(let b) = plan(two, user: "", password: "b") else { return XCTFail("one of them has the password") }
        XCTAssertEqual(b.id, "bob")

        // View-only logins don't count as "the one login", but their password does count as saved.
        let ro = vault([entry("r", user: "alice", password: "old", url: "https://example.com", vault: "ro")])
        guard case .create = plan(ro, user: "", password: "new") else { return XCTFail("no editable login: new login") }
        guard case .unchanged = plan(ro, user: "", password: "old") else { return XCTFail("already saved (view-only)") }
        let mixed = vault([
            entry("r", user: "alice", password: "a", url: "https://example.com", vault: "ro"),
            entry("w", user: "bob", password: "b", url: "https://example.com"),
        ])
        guard case .update(let w, _) = plan(mixed, user: "", password: "new") else { return XCTFail("exactly one editable login") }
        XCTAssertEqual(w.id, "w")
        // Nothing for the site at all.
        guard case .create = plan(vault([]), user: "", password: "new") else { return XCTFail("new login") }
    }

    /// "Save in": the editable logins for the page, the preselection and the user's choice.
    func testSaveTargetsAndChoice() {
        let v = vault([
            entry("bob", user: "bob", password: "b", url: "https://example.com"),
            entry("r", user: "alice", password: "a", url: "https://example.com", vault: "ro"),
            entry("alice", user: "alice", password: "a", url: "https://www.example.com"),
            entry("other", user: "alice", password: "a", url: "https://example.org"),
        ])
        let page = "https://login.example.com/signup"
        func targets(_ vault: VaultData, user: String, password: String) -> [String] {
            SaveLogic.targets(page: page, username: user, password: password, vault: vault, defaultMatch: .domain).map(\.id)
        }
        XCTAssertEqual(targets(v, user: "carol", password: "new"), ["bob", "alice"], "the user's own logins for the page, in matching order")
        XCTAssertEqual(SaveLogic.defaultTarget(plan(v, user: "bob", password: "new")), "bob")
        XCTAssertEqual(SaveLogic.defaultTarget(plan(v, user: "carol", password: "new")), SaveLogic.newLogin)
        XCTAssertEqual(SaveLogic.defaultTarget(plan(v, user: "bob", password: "b")), SaveLogic.newLogin, "unchanged: nothing preselected")

        func chosen(_ target: String, user: String, password: String) -> SaveLogic.Plan? {
            SaveLogic.plan(target: target, page: page, username: user, password: password, vault: v, defaultMatch: .domain)
        }
        guard case .create? = chosen(SaveLogic.newLogin, user: "bob", password: "new") else { return XCTFail("the user chose a new login") }
        guard case .update(let e, _)? = chosen("alice", user: "carol", password: "new") else { return XCTFail("the user chose a login") }
        XCTAssertEqual(e.id, "alice")
        XCTAssertEqual(SaveLogic.updatedItem(e, username: "carol", password: "new").login?.username, "carol", "the typed user name replaces another one")
        guard case .unchanged? = chosen("alice", user: "Alice", password: "a") else { return XCTFail("nothing to change") }
        guard case .unchanged? = chosen("alice", user: "", password: "a") else { return XCTFail("nothing to change without a user name") }
        guard case .update? = chosen("alice", user: "carol", password: "a") else { return XCTFail("same password, other user name: update") }
        XCTAssertNil(chosen("r", user: "alice", password: "new"), "view-only logins can't be chosen")
        XCTAssertNil(chosen("other", user: "alice", password: "new"), "a login for another site can't be chosen")
        XCTAssertNil(chosen("gone", user: "alice", password: "new"))
    }

    func testPlanRespectsMatchingAndVaultRoles() {
        // Host match: login.example.com isn't www.example.com.
        let host = vault([entry("h", user: "alice", password: "old", url: "https://www.example.com", match: .host)])
        guard case .create = plan(host, user: "alice", password: "new") else { return XCTFail("host match doesn't cover login.example.com") }
        // Read-only vault: not updated.
        let ro = vault([entry("r", user: "alice", password: "old", url: "https://example.com", vault: "ro")])
        guard case .readOnly = plan(ro, user: "alice", password: "new") else { return XCTFail("read-only") }
        XCTAssertFalse(plan(ro, user: "alice", password: "new").isChange)
        // A writable copy wins over the read-only one.
        let both = vault([entry("r", user: "alice", password: "old", url: "https://example.com", vault: "ro"), entry("w", user: "alice", password: "old", url: "https://example.com")])
        guard case .update(let e, _) = plan(both, user: "alice", password: "new") else { return XCTFail("update") }
        XCTAssertEqual(e.id, "w")
        // An https login isn't updated from an http page (never downgrade).
        let https = vault([entry("s", user: "alice", password: "old", url: "https://example.com")])
        guard case .create = plan(https, page: "http://example.com/signup", user: "alice", password: "new") else { return XCTFail("http page") }
    }

    // MARK: Save: shared vaults (somebody can share a vault and plant a login in it)

    /// A login without a user name planted in a shared vault with write access is never the
    /// default place a typed user name and password go to, and can't be chosen in "Save in".
    func testPlantedSharedLoginIsNeverTheTarget() {
        let page = "https://login.example.com/signup"
        func targets(_ v: VaultData, user: String, password: String) -> [String] {
            SaveLogic.targets(page: page, username: user, password: password, vault: v, defaultMatch: .domain).map(\.id)
        }
        func chosen(_ v: VaultData, _ target: String, user: String, password: String) -> SaveLogic.Plan? {
            SaveLogic.plan(target: target, page: page, username: user, password: password, vault: v, defaultMatch: .domain)
        }
        let planted = entry("planted", user: "", password: "x", url: "https://example.com", vault: "team")

        // Rule 2 (a user name was typed): a new login, not the planted one.
        let only = vault([planted])
        guard case .create = plan(only, user: "alice", password: "secret") else { return XCTFail("rule 2 must not pick a shared-vault login") }
        XCTAssertEqual(targets(only, user: "alice", password: "secret"), [], "not offered in “Save in”")
        XCTAssertNil(chosen(only, "planted", user: "alice", password: "secret"), "and not accepted as a choice")
        // … even when the planted login already has the typed password.
        guard case .create = plan(vault([entry("planted", user: "", password: "secret", url: "https://example.com", vault: "team")]), user: "alice", password: "secret") else {
            return XCTFail("rule 2 must not pick a shared-vault login by its password")
        }
        // The user's own login without a user name wins, whatever the planted one's password is.
        let both = vault([entry("planted", user: "", password: "secret", url: "https://example.com", vault: "team"), entry("mine", user: "", password: "old", url: "https://example.com")])
        guard case .update(let e, let why) = plan(both, user: "alice", password: "secret") else { return XCTFail("update my own login") }
        XCTAssertEqual(e.id, "mine")
        XCTAssertEqual(why, .blank)
        XCTAssertEqual(targets(both, user: "alice", password: "secret"), ["mine"])

        // Rule 3 (no user name typed): the planted login doesn't count as "the only login" …
        let withMine = vault([planted, entry("mine", user: "alice", password: "old", url: "https://example.com")])
        guard case .update(let mine, let reason) = plan(withMine, user: "", password: "secret") else { return XCTFail("my only own login") }
        XCTAssertEqual(mine.id, "mine", "the planted login is neither rule 1's “same user name” nor rule 3's only login")
        XCTAssertEqual(reason, .only)
        XCTAssertEqual(targets(withMine, user: "", password: "secret"), ["mine"])
        XCTAssertNil(chosen(withMine, "planted", user: "", password: "secret"))
        // … and alone it gives a new login (never an update of the shared one).
        guard case .create = plan(only, user: "", password: "secret") else { return XCTFail("no user name typed: not the planted login") }
        XCTAssertEqual(targets(only, user: "", password: "secret"), [])
        // A shared login with another user name isn't "the only login" either.
        let other = vault([entry("theirs", user: "bob", password: "x", url: "https://example.com", vault: "team")])
        guard case .create = plan(other, user: "", password: "secret") else { return XCTFail("rule 3 counts own logins only") }
        guard case .create = plan(other, user: "alice", password: "secret") else { return XCTFail("another user name: new login") }
        XCTAssertEqual(targets(other, user: "alice", password: "secret"), [])
    }

    /// Rule 1 is unchanged for a typed user name: a shared-vault login with exactly that user
    /// name is updated, is shown as the selection (with its vault), and only then can be chosen.
    func testSharedLoginWithTheSameUserNameIsStillUpdated() {
        let page = "https://login.example.com/signup"
        let v = vault([
            entry("mine", user: "bob", password: "b", url: "https://example.com"),
            entry("shared", user: "Alice", password: "old", url: "https://example.com", vault: "team"),
        ])
        guard case .update(let e, let why) = plan(v, user: "alice", password: "new") else { return XCTFail("rule 1 updates it") }
        XCTAssertEqual(e.id, "shared")
        XCTAssertEqual(why, .same)
        XCTAssertEqual(v.sharedVaultName(e), "Team", "its row shows the vault's name")
        XCTAssertNil(v.sharedVaultName(v.entries[0]))
        XCTAssertEqual(SaveLogic.targets(page: page, username: "alice", password: "new", vault: v, defaultMatch: .domain).map(\.id), ["mine", "shared"],
                       "own logins plus the preselected shared one")
        guard case .update(let c, _)? = SaveLogic.plan(target: "shared", page: page, username: "alice", password: "new", vault: v, defaultMatch: .domain) else {
            return XCTFail("the displayed selection is accepted")
        }
        XCTAssertEqual(c.id, "shared")
        // For another user name it is not offered and not accepted.
        XCTAssertEqual(SaveLogic.targets(page: page, username: "carol", password: "new", vault: v, defaultMatch: .domain).map(\.id), ["mine"])
        XCTAssertNil(SaveLogic.plan(target: "shared", page: page, username: "carol", password: "new", vault: v, defaultMatch: .domain))
        guard case .unchanged = plan(v, user: "alice", password: "old") else { return XCTFail("already saved there") }
    }

    /// No password: nothing to save, whatever the caller checked before.
    func testPlanWithoutPassword() {
        let v = vault([entry("a", user: "alice", password: "old", url: "https://example.com")])
        guard case .noPassword = plan(v, user: "alice", password: "") else { return XCTFail("no password: nothing") }
        XCTAssertFalse(plan(v, user: "alice", password: "").isChange)
        guard case .noPassword = plan(v, user: "", password: "") else { return XCTFail("no password: nothing") }
        guard case .noPassword? = SaveLogic.plan(target: "a", page: "https://example.com/", username: "alice", password: "", vault: v, defaultMatch: .domain) else {
            return XCTFail("a chosen login is never blanked")
        }
        guard case .noPassword? = SaveLogic.plan(target: SaveLogic.newLogin, page: "https://example.com/", username: "alice", password: "", vault: v, defaultMatch: .domain) else {
            return XCTFail("no empty new login")
        }
        XCTAssertEqual(SaveLogic.defaultTarget(plan(v, user: "alice", password: "")), SaveLogic.newLogin)
    }

    // MARK: Password rules

    func testParseRules() throws {
        let r = try XCTUnwrap(PasswordRules.parse("required: upper; required: digit; required: [-().&@?'#,/\"+]; allowed: lower; max-consecutive: 2; minlength: 10; maxlength: 16;"))
        XCTAssertEqual(r.minLength, 10)
        XCTAssertEqual(r.maxLength, 16)
        XCTAssertEqual(r.maxConsecutive, 2)
        XCTAssertEqual(r.required.count, 3)
        XCTAssertEqual(r.required[2], Set("-().&@?'#,/\"+"))
        XCTAssertEqual(r.allowed, PasswordRules.upper.union(PasswordRules.digit).union(PasswordRules.lower).union(Set("-().&@?'#,/\"+")))
        // Custom class containing ";" and "]" first.
        let c = try XCTUnwrap(PasswordRules.parse("ALLOWED: [];x]; minlength: 8"))
        XCTAssertEqual(c.allowed, Set("];x"))
        // Only lengths: any printable ASCII.
        XCTAssertEqual(PasswordRules.parse("minlength: 12")?.allowed, PasswordRules.asciiPrintable)
        XCTAssertNil(PasswordRules.parse("  "))
        XCTAssertNil(PasswordRules.parse("foo: bar"))
        XCTAssertNil(PasswordRules.parse("allowed: unicode")?.allowed)
    }

    func testRulesAccept() throws {
        let r = try XCTUnwrap(PasswordRules.parse("required: lower; required: digit; max-consecutive: 2; minlength: 8; maxlength: 10"))
        XCTAssertTrue(r.accepts("abcd1234"))
        XCTAssertFalse(r.accepts("abcd12345678"), "too long")
        XCTAssertFalse(r.accepts("abcdefgh"), "no digit")
        XCTAssertFalse(r.accepts("aaab1234"), "three in a row")
        XCTAssertFalse(r.accepts("abcd123!"), "! not allowed")
    }

    func testRequestRulesPriority() {
        XCTAssertEqual(PasswordGeneration.rules(field: nil, quirks: "maxlength: 12", confirm: "maxlength: 30")?.maxLength, 12)
        XCTAssertEqual(PasswordGeneration.rules(field: "maxlength: 20", quirks: "maxlength: 12", confirm: nil)?.maxLength, 20)
        XCTAssertEqual(PasswordGeneration.rules(field: "", quirks: nil, confirm: "maxlength: 30")?.maxLength, 30)
        XCTAssertNil(PasswordGeneration.rules(field: nil, quirks: nil, confirm: nil))
    }

    // MARK: Rules → generator

    func testPlanWithoutRulesUsesSettings() {
        var user = GeneratorSettings()
        user.length = 24
        user.symbols = false
        let p = PasswordGeneration.plan(rules: nil, user: user)
        XCTAssertTrue(p.followsRules)
        XCTAssertEqual(p.options.length, 24)
        XCTAssertFalse(p.options.symbols)
        XCTAssertNil(p.symbolSet)
    }

    func testPlanLengthAndClasses() throws {
        let rules = try XCTUnwrap(PasswordRules.parse("required: lower; required: upper; required: digit; maxlength: 12"))
        let p = PasswordGeneration.plan(rules: rules, user: GeneratorSettings())
        XCTAssertTrue(p.followsRules)
        XCTAssertEqual(p.options.length, 12, "user's 20 limited to the site's maximum")
        XCTAssertFalse(p.options.symbols, "no special characters allowed")
        XCTAssertTrue(p.options.lowercase && p.options.uppercase && p.options.digits)
        // Minimum above the user's length.
        let long = PasswordGeneration.plan(rules: PasswordRules.parse("minlength: 30"), user: GeneratorSettings())
        XCTAssertEqual(long.options.length, 30)
        XCTAssertTrue(long.options.symbols)
        XCTAssertNil(long.symbolSet, "all specials allowed: the core's own symbols")
    }

    func testPlanTurnsOnRequiredClasses() throws {
        var user = GeneratorSettings()
        user.digits = false
        user.symbols = false
        let p = PasswordGeneration.plan(rules: PasswordRules.parse("required: digit; required: special; allowed: lower, upper"), user: user)
        XCTAssertTrue(p.followsRules)
        XCTAssertTrue(p.options.digits, "required digit turned on")
        XCTAssertTrue(p.options.symbols, "required special turned on")
    }

    func testPlanRestrictedSymbols() throws {
        let rules = try XCTUnwrap(PasswordRules.parse("required: lower; required: upper; required: digit; required: [-_.]; minlength: 12; maxlength: 20"))
        let p = PasswordGeneration.plan(rules: rules, user: GeneratorSettings())
        XCTAssertTrue(p.followsRules)
        XCTAssertEqual(p.symbolSet.map { Set($0) }, Set("-_."))
        for _ in 0..<50 {
            let pw = try XCTUnwrap(PasswordGeneration.password(p))
            XCTAssertTrue(rules.accepts(pw), pw)
            XCTAssertTrue(pw.contains { "-_.".contains($0) }, pw)
        }
    }

    func testPlanMaxConsecutiveAndAmbiguous() throws {
        var user = GeneratorSettings()
        user.avoidAmbiguous = true
        let rules = try XCTUnwrap(PasswordRules.parse("required: digit; allowed: lower; max-consecutive: 1; minlength: 16; maxlength: 16"))
        let p = PasswordGeneration.plan(rules: rules, user: user)
        XCTAssertTrue(p.followsRules)
        for _ in 0..<30 {
            let pw = try XCTUnwrap(PasswordGeneration.password(p))
            XCTAssertTrue(rules.accepts(pw), pw)
            XCTAssertFalse(pw.contains { "Il1O0o".contains($0) }, pw)
        }
    }

    func testUnsatisfiableRulesFallBackToSettings() throws {
        var user = GeneratorSettings()
        user.length = 18
        // A required set no whole class covers.
        let custom = PasswordGeneration.plan(rules: PasswordRules.parse("required: [abc]; allowed: lower"), user: user)
        XCTAssertFalse(custom.followsRules)
        XCTAssertEqual(custom.options.length, 18)
        XCTAssertTrue(custom.options.symbols, "the user's settings")
        // Shorter than the core's minimum of 8.
        XCTAssertFalse(PasswordGeneration.plan(rules: PasswordRules.parse("maxlength: 6"), user: user).followsRules)
        XCTAssertFalse(PasswordGeneration.plan(rules: PasswordRules.parse("minlength: 20; maxlength: 10"), user: user).followsRules)
        let fallback = try XCTUnwrap(PasswordGeneration.password(custom))
        XCTAssertEqual(fallback.count, 18)
    }

    func testCandidates() throws {
        var user = GeneratorSettings()
        let plain = PasswordGeneration.candidates(rules: nil, user: user).list
        XCTAssertEqual(plain.map(\.kind), [.strong, .alphanumeric, .passphrase])
        XCTAssertEqual(plain[0].value.count, 20)
        XCTAssertTrue(plain[1].value.allSatisfy { $0.isLetter || $0.isNumber })
        user.passphrase = true
        XCTAssertEqual(PasswordGeneration.candidates(rules: nil, user: user).list.first?.kind, .passphrase, "preferred type first")
        // Site needs a special character and at most 16 characters: no symbol-free or passphrase option.
        let rules = try XCTUnwrap(PasswordRules.parse("required: lower; required: special; maxlength: 16"))
        let strict = PasswordGeneration.candidates(rules: rules, user: user).list
        XCTAssertEqual(strict.map(\.kind), [.strong])
        XCTAssertTrue(rules.accepts(strict[0].value))
    }
}

/// `VaultRepository.saveLogin` against the recording fake server: an update keeps the old
/// password in the history, another user name becomes a new login, an equal password sends nothing.
@MainActor
final class SaveLoginRepoTests: XCTestCase {
    private var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pa-save-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        RecordingServer.requests = []
    }

    override func tearDown() async throws {
        SecureStore.wipeAll(directory: dir)
        try? FileManager.default.removeItem(at: dir)
    }

    func testSaveLogin() async throws {
        let password = "correct horse battery staple"
        let created = try createAccount(accountId: try newId(), password: password, withSecretKey: false)
        let a = try newId()
        let ka = try created.account.newVaultKey(vaultId: a)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Example"
        item.login?.username = "alice"
        item.login?.password = "pw-1"
        item.login?.urls = [LoginUrl(url: "https://example.com", match: .default)]
        let itemId = try newId()
        let enc = try ka.key.encryptItem(itemJson: ItemCodec.encode(item), id: itemId, vaultId: a)
        // A login saved with only a password.
        var bare = Item.empty(.login, now: 1_700_000_000)
        bare.name = "Bare"
        bare.login?.password = "only-pw"
        bare.login?.urls = [LoginUrl(url: "https://bare.example.net", match: .default)]
        let bareId = try newId()
        let bareEnc = try ka.key.encryptItem(itemJson: ItemCodec.encode(bare), id: bareId, vaultId: a)
        RecordingServer.syncBody = try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": a, "wrapped_key": ka.wrapped, "key_kind": "account", "meta": try ka.key.encryptMeta(vaultId: a, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [
                ["id": itemId, "vault_id": a, "item_key": enc.key, "data": enc.data, "revision": 2],
                ["id": bareId, "vault_id": a, "item_key": bareEnc.key, "data": bareEnc.data, "revision": 2],
            ],
            "revision": 2,
        ] as [String: Any])
        let store = SecureStore(directory: dir, role: .app)
        store.load()
        store.update { s in
            var acc = AccountData(server: "https://fake.passauth.test", email: "a@example.com")
            acc.bundle = created.bundleJson
            s.file.accounts["acc"] = acc
            s.file.activeId = "acc"
            s.secrets.tokens["acc"] = Tokens(access: "A", refresh: "R")
        }
        let repo = VaultRepository(store: store, api: ApiClient(store: store) { $0.protocolClasses = [RecordingServer.self] })
        try await repo.unlock(password: password, secretKey: nil)
        func decrypt(_ body: [String: Any], id: String) throws -> Item {
            try ItemCodec.decode(try ka.key.decryptItem(encrypted: EncryptedItem(id: id, vaultId: a, key: body["key"] as! String, data: body["data"] as! String)))
        }

        // Same site (base domain) and user name, same password: nothing to send.
        RecordingServer.requests = []
        let same = try await repo.saveLogin(page: "https://www.example.com/login", username: "Alice", password: "pw-1")
        XCTAssertEqual(same, .unchanged)
        XCTAssertTrue(RecordingServer.requests.isEmpty)

        // New password: PUT with the old one in the history and the item's revision.
        let updated = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "pw-2")
        XCTAssertEqual(updated, .updated)
        let put = try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" })
        XCTAssertEqual(put.path, "/api/items/\(itemId)")
        XCTAssertEqual((put.body["revision"] as? NSNumber)?.int64Value, 2)
        let saved = try decrypt(put.body, id: itemId)
        XCTAssertEqual(saved.login?.password, "pw-2")
        XCTAssertEqual(saved.passwordHistory.map(\.password), ["pw-1"])
        XCTAssertEqual(saved.name, "Example")

        // Another user name: a new login for the page's origin.
        RecordingServer.requests = []
        let new = try await repo.saveLogin(page: "https://shop.example.com/signup", username: "bob", password: "pw-b")
        XCTAssertEqual(new, .created)
        let post = try XCTUnwrap(RecordingServer.requests.first { $0.method == "POST" && $0.path == "/api/items" })
        let newItem = try decrypt(post.body, id: post.body["id"] as! String)
        XCTAssertEqual(newItem.name, "shop.example.com")
        XCTAssertEqual(newItem.login?.username, "bob")
        XCTAssertEqual(newItem.login?.password, "pw-b")
        XCTAssertEqual(newItem.login?.urls, [LoginUrl(url: "https://shop.example.com", match: .default)])

        // Only a password was saved for the site: the typed user name goes into that login
        // (no second login); the password is the same, so nothing goes to the history.
        RecordingServer.requests = []
        let filled = try await repo.saveLogin(page: "https://bare.example.net/login", username: " carol ", password: "only-pw")
        XCTAssertEqual(filled, .updated)
        XCTAssertNil(RecordingServer.requests.first { $0.method == "POST" && $0.path == "/api/items" })
        let barePut = try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" })
        XCTAssertEqual(barePut.path, "/api/items/\(bareId)")
        let bareSaved = try decrypt(barePut.body, id: bareId)
        XCTAssertEqual(bareSaved.login?.username, "carol")
        XCTAssertEqual(bareSaved.login?.password, "only-pw")
        XCTAssertEqual(bareSaved.passwordHistory, [])
        XCTAssertEqual(bareSaved.name, "Bare")

        // "Save in" → New login: a new login although the default plan would update.
        RecordingServer.requests = []
        let forced = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "pw-3", target: SaveLogic.newLogin)
        XCTAssertEqual(forced, .created)
        XCTAssertNil(RecordingServer.requests.first { $0.method == "PUT" })
        XCTAssertNotNil(RecordingServer.requests.first { $0.method == "POST" && $0.path == "/api/items" })

        // "Save in" → a chosen login: updated with the typed user name and password.
        RecordingServer.requests = []
        let picked = try await repo.saveLogin(page: "https://www.example.com/password", username: "dave", password: "pw-4", target: itemId)
        XCTAssertEqual(picked, .updated)
        let pickedPut = try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" })
        let pickedItem = try decrypt(pickedPut.body, id: itemId)
        XCTAssertEqual(pickedItem.login?.username, "dave")
        XCTAssertEqual(pickedItem.login?.password, "pw-4")
        XCTAssertEqual(pickedItem.passwordHistory.map(\.password), ["pw-1"])

        // No user name typed and one login for the site (rule 3): never without the sheet …
        RecordingServer.requests = []
        do {
            _ = try await repo.saveLogin(page: "https://www.example.com/password", username: "", password: "pw-7")
            XCTFail("a rule-3 update needs the sheet")
        } catch let e {
            XCTAssertTrue(e is VaultRepository.SaveChoiceChanged, "\(e)")
        }
        XCTAssertNil(RecordingServer.requests.first { $0.method == "PUT" || $0.method == "POST" })
        // … but applied once the sheet showed it as the selection: the password only, the user name kept.
        let only = try await repo.saveLogin(page: "https://www.example.com/password", username: "", password: "pw-7", target: itemId, isDefault: true)
        XCTAssertEqual(only, .updated)
        let onlyItem = try decrypt(try XCTUnwrap(RecordingServer.requests.first { $0.method == "PUT" }).body, id: itemId)
        XCTAssertEqual(onlyItem.login?.username, "alice")
        XCTAssertEqual(onlyItem.login?.password, "pw-7")

        // The sheet's untouched default no longer is the synced vault's default (it showed "New
        // login", the vault has this user's login by now): nothing is written, the sheet asks again.
        RecordingServer.requests = []
        do {
            _ = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "pw-8", target: SaveLogic.newLogin, isDefault: true)
            XCTFail("the displayed default is stale")
        } catch let e {
            XCTAssertTrue(e is VaultRepository.SaveChoiceChanged, "\(e)")
        }
        XCTAssertNil(RecordingServer.requests.first { $0.method == "PUT" || $0.method == "POST" })
        // Saved meanwhile with this very password: nothing to do, no second login.
        let already = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "pw-1", target: SaveLogic.newLogin, isDefault: true)
        XCTAssertEqual(already, .unchanged)
        XCTAssertNil(RecordingServer.requests.first { $0.method == "PUT" || $0.method == "POST" })

        // No password: refused before anything is asked of the server (a saved one is never blanked).
        RecordingServer.requests = []
        for target in [nil, itemId, SaveLogic.newLogin] {
            do {
                _ = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "", target: target)
                XCTFail("no password to save")
            } catch {}
        }
        XCTAssertTrue(RecordingServer.requests.isEmpty)

        // A chosen login that isn't for this page (or is gone): refused, nothing sent.
        RecordingServer.requests = []
        do {
            _ = try await repo.saveLogin(page: "https://www.example.com/password", username: "alice", password: "pw-5", target: bareId)
            XCTFail("a login for another site can't be the target")
        } catch {}
        XCTAssertNil(RecordingServer.requests.first { $0.method == "PUT" || $0.method == "POST" })
    }

    /// The extension declares the iOS 26.2 save / generate capabilities.
    func testExtensionCapabilities() throws {
        let url = try XCTUnwrap(Bundle.main.builtInPlugInsURL?.appendingPathComponent("PassAuthAutoFill.appex/Info.plist"))
        let plist = try XCTUnwrap(NSDictionary(contentsOf: url) as? [String: Any])
        let caps = try XCTUnwrap(((plist["NSExtension"] as? [String: Any])?["NSExtensionAttributes"] as? [String: Any])?["ASCredentialProviderExtensionCapabilities"] as? [String: Any])
        XCTAssertEqual(caps["SupportsSavePasswordCredentials"] as? Bool, true)
        XCTAssertEqual(caps["SupportsGeneratePasswordCredentials"] as? Bool, true)
        XCTAssertEqual(caps["ProvidesPasswords"] as? Bool, true)
    }
}
