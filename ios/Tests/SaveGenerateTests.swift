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
        v.vaults = [VaultInfo(id: "v1", name: "Personal", role: .owner), VaultInfo(id: "ro", name: "Shared", role: .read)]
        return v
    }

    private func plan(_ v: VaultData, page: String = "https://login.example.com/signup", user: String, password: String) -> SaveLogic.Plan {
        SaveLogic.plan(page: page, username: user, password: password, vault: v, defaultMatch: .domain, server: "https://vault.example.org")
    }

    // MARK: Save: offer or not

    func testSaveBlocked() {
        var s = Settings()
        let server = "https://pass.example.org"
        XCTAssertNil(SaveLogic.blocked(page: "https://www.shop.co.uk/register", password: "pw", settings: s, server: server))
        XCTAssertEqual(SaveLogic.blocked(page: "https://pass.example.org/login", password: "pw", settings: s, server: server), .vaultPage)
        XCTAssertEqual(SaveLogic.blocked(page: nil, password: "pw", settings: s, server: server), .notWebsite, "apps without a domain")
        XCTAssertEqual(SaveLogic.blocked(page: "https://example.com/", password: "", settings: s, server: server), .noPassword)
        s.neverSave = ["shop.co.uk"]
        XCTAssertEqual(SaveLogic.blocked(page: "https://accounts.shop.co.uk/x", password: "pw", settings: s, server: server), .neverSave, "keyed by base domain")
        XCTAssertNil(SaveLogic.blocked(page: "https://example.com/", password: "pw", settings: s, server: server))
        s.askToSave = false
        XCTAssertEqual(SaveLogic.blocked(page: "https://example.com/", password: "pw", settings: s, server: server), .askToSaveOff)
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
        guard case .update(let e) = plan(v, user: "alice", password: "new") else { return XCTFail("update") }
        XCTAssertEqual(e.id, "alice", "same base domain, user name case-insensitive")
        let item = SaveLogic.updatedItem(e, password: "new")
        XCTAssertEqual(item.login?.password, "new")
        XCTAssertEqual(item.login?.username, "Alice")
        XCTAssertEqual(item.passwordHistory, [], "the repository's updateItem adds the old password to the history")
        guard case .unchanged = plan(v, user: "alice", password: "old") else { return XCTFail("same password: nothing to do") }
        guard case .create = plan(v, user: "carol", password: "x") else { return XCTFail("other user: new login") }
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
        guard case .update(let e) = plan(both, user: "alice", password: "new") else { return XCTFail("update") }
        XCTAssertEqual(e.id, "w")
        // An https login isn't updated from an http page (never downgrade).
        let https = vault([entry("s", user: "alice", password: "old", url: "https://example.com")])
        guard case .create = plan(https, page: "http://example.com/signup", user: "alice", password: "new") else { return XCTFail("http page") }
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
        RecordingServer.syncBody = try JSONSerialization.data(withJSONObject: [
            "vaults": [["id": a, "wrapped_key": ka.wrapped, "key_kind": "account", "meta": try ka.key.encryptMeta(vaultId: a, metaJson: #"{"name":"Personal"}"#), "role": "owner"]],
            "items": [["id": itemId, "vault_id": a, "item_key": enc.key, "data": enc.data, "revision": 2]],
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
