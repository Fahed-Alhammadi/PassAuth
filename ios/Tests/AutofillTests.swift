import AuthenticationServices
import CryptoKit
import PassAuthCore
import PassAuthKit
import XCTest

/// AutoFill extension logic: service identifier matching, identity store mapping, passkeys.
@MainActor
final class AutofillTests: XCTestCase {
    private func entry(_ id: String, name: String, user: String, password: String = "pw", urls: [(String, UrlMatch)], totp: String? = nil, passkeys: [Passkey] = [], vault: String = "v1") -> Entry {
        var login = Login(username: user, password: password, urls: urls.map { LoginUrl(url: $0.0, match: $0.1) }, totp: totp)
        login.passkeys = passkeys
        let item = Item(name: name, login: login)
        return Entry(id: id, item: item, vaultId: vault, revision: 1, enc: EncryptedItem(id: id, vaultId: vault, key: "", data: ""), deletedAt: nil)
    }

    private func vault(_ entries: [Entry], role: Role = .owner) -> VaultData {
        var v = VaultData()
        v.entries = entries
        v.vaults = [VaultInfo(id: "v1", name: "Personal", role: role), VaultInfo(id: "ro", name: "Shared", role: .read)]
        return v
    }

    // MARK: Service identifiers

    func testPagesFromServiceIdentifiers() {
        XCTAssertEqual(AutofillMatcher.page("https://login.example.com/signin?x=1", isURL: true), "https://login.example.com/signin?x=1")
        XCTAssertEqual(AutofillMatcher.page("Example.COM.", isURL: false), "https://example.com/")
        XCTAssertNil(AutofillMatcher.page("ftp://example.com/", isURL: true))
        XCTAssertNil(AutofillMatcher.page("", isURL: false))
        let ids = [
            ASCredentialServiceIdentifier(identifier: "http://localhost:8099/login.html", type: .URL),
            ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
            ASCredentialServiceIdentifier(identifier: "example.com", type: .domain),
        ]
        XCTAssertEqual(AutofillMatcher.pages(ids), ["http://localhost:8099/login.html", "https://example.com/"])
    }

    func testDomainVersusUrlMatching() {
        let domain = entry("1", name: "Domain", user: "a", urls: [("https://www.example.com/login", .default)])
        let host = entry("2", name: "Host", user: "b", urls: [("https://www.example.com", .host)])
        let exact = entry("3", name: "Exact", user: "c", urls: [("https://example.com/signin", .exact)])
        let starts = entry("4", name: "Starts", user: "d", urls: [("https://example.com/", .startsWith)])
        let app = entry("5", name: "App", user: "e", urls: [("androidapp://com.example", .default)])
        let other = entry("6", name: "Other", user: "f", urls: [("https://example.org", .default)])
        let all = [domain, host, exact, starts, app, other]
        // Safari: the full page URL.
        let url = AutofillMatcher.candidates(["https://example.com/signin"], all, defaultMatch: .domain, server: "")
        XCTAssertEqual(url.map(\.id), ["1", "3", "4"])
        // An app's associated domain: only scheme and host, so "exact" sees https://example.com/.
        let dom = AutofillMatcher.candidates([AutofillMatcher.page("example.com", isURL: false)!], all, defaultMatch: .domain, server: "")
        XCTAssertEqual(dom.map(\.id), ["1", "4"])
        let www = AutofillMatcher.candidates([AutofillMatcher.page("www.example.com", isURL: false)!], all, defaultMatch: .host, server: "")
        XCTAssertEqual(www.map(\.id), ["1", "2"], "default match = host: both www logins, not the bare-domain ones")
    }

    func testDowngradeAndVaultPageRefused() {
        let https = entry("1", name: "Secure", user: "a", urls: [("https://example.com", .default)])
        let local = entry("2", name: "Local", user: "b", urls: [("http://localhost:8099", .default)])
        XCTAssertTrue(AutofillMatcher.candidates(["http://example.com/login"], [https], defaultMatch: .domain, server: "").isEmpty, "https login never on an http page")
        XCTAssertEqual(AutofillMatcher.candidates(["http://localhost:8099/login.html"], [local], defaultMatch: .domain, server: "").map(\.id), ["2"])
        let vaultLogin = entry("3", name: "Vault", user: "c", urls: [("https://vault.example.net", .default)])
        XCTAssertTrue(AutofillMatcher.isVaultPage("https://vault.example.net/vault", server: "https://vault.example.net"))
        XCTAssertTrue(AutofillMatcher.candidates(["https://vault.example.net/"], [vaultLogin], defaultMatch: .domain, server: "https://vault.example.net").isEmpty)
    }

    func testSearch() {
        let a = entry("1", name: "Mail", user: "alice@example.com", urls: [("https://mail.example.com", .default)])
        let b = entry("2", name: "Bank", user: "bob", urls: [("https://bank.test", .default)])
        XCTAssertEqual(AutofillMatcher.search("ALICE", [a, b]).map(\.id), ["1"])
        XCTAssertEqual(AutofillMatcher.search("bank.test", [a, b]).map(\.id), ["2"])
        XCTAssertEqual(AutofillMatcher.search(" ", [a, b]).count, 2)
    }

    // MARK: Identity store

    func testIdentityRecordsMapping() {
        var pk = Passkey()
        pk.credentialId = PasskeyLogic.b64url(Data([1, 2, 3, 4]))
        pk.rpId = "Example.com"
        pk.userName = "alice"
        pk.userHandle = PasskeyLogic.b64url(Data("user-1".utf8))
        let entries = [
            entry("1", name: "Example", user: "alice", password: "s3cret-pass", urls: [("https://www.example.com/login", .default), ("https://example.com", .domain)], totp: "JBSWY3DPEHPK3PXP", passkeys: [pk]),
            entry("2", name: "Exact", user: "bob", password: "other-secret", urls: [("https://shop.test/account", .exact), ("https://shop.test", .host)]),
            entry("3", name: "Skipped", user: "carol", password: "x", urls: [("^https://.*", .regex), ("androidapp://com.x", .default), ("https://never.test", .never), ("ssh://host", .default)]),
            entry("4", name: "Server", user: "dave", password: "x", urls: [("https://pa.example.org", .default), ("https://pa.example.org/login", .host)]),
        ]
        let r = IdentityMapper.records(entries, defaultMatch: .domain, server: "https://pa.example.org")
        let passwords = r.filter { $0.kind == .password }
        XCTAssertEqual(passwords.map(\.service), ["example.com", "https://shop.test/account", "https://shop.test"], "deduplicated, regex/never/app/non-web and the server's host left out")
        XCTAssertEqual(passwords.map(\.serviceType), [.domain, .url, .url])
        XCTAssertEqual(passwords.map(\.recordId), ["1", "2", "2"])
        XCTAssertEqual(passwords.first?.user, "alice")
        XCTAssertEqual(r.filter { $0.kind == .oneTimeCode }.map(\.service), ["example.com"])
        let passkeys = r.filter { $0.kind == .passkey }
        XCTAssertEqual(passkeys.count, 1)
        XCTAssertEqual(passkeys.first?.service, "example.com")
        XCTAssertEqual(passkeys.first?.credentialId, Data([1, 2, 3, 4]))
        XCTAssertEqual(passkeys.first?.userHandle, Data("user-1".utf8))
        // Never a secret in the store.
        for rec in r {
            XCTAssertFalse("\(rec)".contains("s3cret-pass") || "\(rec)".contains("other-secret") || "\(rec)".contains("JBSWY3DP"))
        }
        // The system objects carry the same data.
        let ids = IdentityMapper.identities(r)
        let pw = ids.compactMap { $0 as? ASPasswordCredentialIdentity }
        XCTAssertEqual(pw.first?.serviceIdentifier.type, .domain)
        XCTAssertEqual(pw.first?.recordIdentifier, "1")
        XCTAssertEqual(ids.compactMap { $0 as? ASPasskeyCredentialIdentity }.first?.relyingPartyIdentifier, "example.com")
        if #available(iOS 18.0, macOS 15.0, *) {
            XCTAssertEqual(ids.compactMap { $0 as? ASOneTimeCodeCredentialIdentity }.first?.label, "Example")
        }
    }

    func testDefaultMatchChangesIdentities() {
        let e = [entry("1", name: "Example", user: "alice", urls: [("https://www.example.com/login", .default)])]
        XCTAssertEqual(IdentityMapper.records(e, defaultMatch: .domain, server: "").map(\.service), ["example.com"])
        XCTAssertEqual(IdentityMapper.records(e, defaultMatch: .host, server: "").map(\.service), ["https://www.example.com"])
        XCTAssertEqual(IdentityMapper.records(e, defaultMatch: .exact, server: "").map(\.service), ["https://www.example.com/login"])
        XCTAssertTrue(IdentityMapper.records(e, defaultMatch: .never, server: "").isEmpty)
    }

    func testIdentitySyncWritesOnlyChanges() {
        let sync = CredentialIdentitySync()
        var writes: [[IdentityRecord]?] = []
        sync.sink = { writes.append($0) }
        let r = IdentityMapper.records([entry("1", name: "A", user: "a", urls: [("https://a.test", .default)])], defaultMatch: .domain, server: "")
        sync.replace(r)
        sync.replace(r)
        XCTAssertEqual(writes.count, 1)
        sync.clear()
        sync.clear()
        XCTAssertEqual(writes.count, 2)
        XCTAssertNil(writes.last!)
        sync.replace(r)
        sync.invalidate()
        sync.replace(r)
        XCTAssertEqual(writes.count, 4)
    }

    func testIdentitySyncSeedsFromPersistedFingerprint() {
        let r = IdentityMapper.records([entry("1", name: "A", user: "a", urls: [("https://a.test", .default)])], defaultMatch: .domain, server: "")
        let other = IdentityMapper.records([entry("2", name: "B", user: "b", urls: [("https://b.test", .default)])], defaultMatch: .domain, server: "")
        // The fingerprint is handed out after a write (here: the test sink took it).
        let first = CredentialIdentitySync()
        var persisted: [String?] = []
        first.sink = { _ in }
        first.onWritten = { persisted.append($0) }
        first.replace(r)
        XCTAssertEqual(persisted.count, 1)
        guard let fp = persisted[0], !fp.isEmpty else { return XCTFail("no fingerprint") }
        first.clear()
        XCTAssertEqual(persisted.last, "")

        // The next process, seeded with it, doesn't rewrite the same records; only the first seed counts.
        let next = CredentialIdentitySync()
        var writes: [[IdentityRecord]?] = []
        next.sink = { writes.append($0) }
        next.seed(fp)
        next.replace(r)
        XCTAssertEqual(writes.count, 0)
        next.replace(other)
        XCTAssertEqual(writes.count, 1)
        next.seed(fp)
        next.replace(r)
        XCTAssertEqual(writes.count, 2)

        // Seeded "" (store emptied): a clear is skipped, a replace writes.
        let empty = CredentialIdentitySync()
        var emptyWrites = 0
        empty.sink = { _ in emptyWrites += 1 }
        empty.seed("")
        empty.clear()
        XCTAssertEqual(emptyWrites, 0)
        empty.replace(r)
        XCTAssertEqual(emptyWrites, 1)

        // invalidate forgets the persisted value too and wins over a later seed.
        let reset = CredentialIdentitySync()
        var resetWrites = 0
        var resetPersisted: [String?] = []
        reset.sink = { _ in resetWrites += 1 }
        reset.onWritten = { resetPersisted.append($0) }
        reset.invalidate()
        XCTAssertEqual(resetPersisted.count, 1)
        XCTAssertNil(resetPersisted[0])
        reset.seed(fp)
        reset.replace(r)
        XCTAssertEqual(resetWrites, 1)
        XCTAssertEqual(resetPersisted.last, fp)
    }

    // MARK: Passkeys

    func testPasskeyRegistrationAssertionAndStoredShape() throws {
        // What iOS passes: the RP ID, user name, user handle and the client data hash.
        let rpId = "localhost"
        let userHandle = Data("user-123".utf8)
        let created = try passkeyCreate(rpId: rpId)
        let p = PasskeyLogic.record(rpId: rpId, userName: "alice@localhost", userHandle: userHandle, created: created, now: 1_700_000_000)
        XCTAssertEqual(p.rpId, "localhost")
        XCTAssertEqual(p.userName, "alice@localhost")
        XCTAssertEqual(PasskeyLogic.b64urlDecode(p.userHandle), userHandle)
        XCTAssertEqual(PasskeyLogic.b64urlDecode(p.credentialId), created.credentialId)
        XCTAssertEqual(p.algorithm, -7)
        XCTAssertEqual(p.counter, 0)
        XCTAssertTrue(p.discoverable)
        XCTAssertFalse(p.privateKey.contains("="), "unpadded base64url like the extension")

        // Registration authenticator data: rpIdHash, flags UP|UV|BE|BS|AT, counter 0, AAGUID.
        let auth = created.authenticatorData
        XCTAssertEqual(auth.prefix(32), Data(SHA256.hash(data: Data(rpId.utf8))))
        XCTAssertEqual(auth[32], 0x5D)
        XCTAssertEqual(auth[33..<37], Data([0, 0, 0, 0]))
        XCTAssertEqual(auth[37..<53], Data([0xbb, 0xc7, 0x47, 0xa1, 0x4f, 0xf9, 0x29, 0xdf, 0x65, 0x33, 0xdf, 0xaa, 0x44, 0xf8, 0x6a, 0x18]))

        // New login for https://<rpId> (no login for this site and user yet).
        let empty = vault([entry("x", name: "Other", user: "alice@localhost", urls: [("https://example.com", .default)])])
        guard case .create(let item) = PasskeyLogic.storePlan(empty, p) else { return XCTFail("expected a new login") }
        XCTAssertEqual(item.name, "localhost")
        XCTAssertEqual(item.login?.username, "alice@localhost")
        XCTAssertEqual(item.login?.password, "")
        XCTAssertEqual(item.login?.urls, [LoginUrl(url: "https://localhost", match: .default)])
        XCTAssertEqual(item.login?.passkeys, [p])
        // The stored JSON uses the web/extension field names (snake case).
        let json = try JSON.parse(ItemCodec.encode(item))
        let stored = json["login"]?["passkeys"]?.array.first
        XCTAssertEqual(stored?.str("credential_id"), p.credentialId)
        XCTAssertEqual(stored?.str("rp_id"), "localhost")
        XCTAssertEqual(stored?.str("user_handle"), p.userHandle)

        // Same site and user name: attached to that login; read-only vaults are skipped.
        let existing = entry("e1", name: "Local", user: "Alice@Localhost", urls: [("http://localhost:8099", .default)])
        guard case .attach(let e, let updated) = PasskeyLogic.storePlan(vault([existing]), p) else { return XCTFail("expected attach") }
        XCTAssertEqual(e.id, "e1")
        XCTAssertEqual(updated.login?.passkeys.count, 1)
        XCTAssertEqual(updated.login?.password, "pw")
        let readOnly = entry("e2", name: "Local", user: "alice@localhost", urls: [("http://localhost:8099", .default)], vault: "ro")
        guard case .create = PasskeyLogic.storePlan(vault([readOnly]), p) else { return XCTFail("read-only vault must not be used") }

        // excludeCredentials and allowCredentials.
        XCTAssertTrue(PasskeyLogic.excludedExists([created.credentialId], rpId: "LOCALHOST", all: [p]))
        XCTAssertFalse(PasskeyLogic.excludedExists([Data([9])], rpId: rpId, all: [p]))
        XCTAssertFalse(PasskeyLogic.excludedExists([created.credentialId], rpId: "example.com", all: [p]))
        let withKey = entry("k", name: "Local", user: "alice@localhost", urls: [], passkeys: [p])
        XCTAssertEqual(PasskeyLogic.matching(rpId: rpId, allowed: [], [(withKey, p)]).count, 1)
        XCTAssertEqual(PasskeyLogic.matching(rpId: rpId, allowed: [Data([7])], [(withKey, p)]).count, 0)
        XCTAssertEqual(PasskeyLogic.matching(rpId: rpId, allowed: [created.credentialId], [(withKey, p)]).count, 1)

        // Assertion: the OS's clientDataHash is signed as given (authData || hash, ES256).
        let hash = Data(SHA256.hash(data: Data(#"{"type":"webauthn.get"}"#.utf8)))
        let a = try passkeyAssert(privateKeyPkcs8: PasskeyLogic.b64urlDecode(p.privateKey)!, rpId: rpId, clientDataHash: hash)
        XCTAssertEqual(a.authenticatorData.count, 37)
        XCTAssertEqual(a.authenticatorData[32], 0x1D)
        let key = try P256.Signing.PublicKey(derRepresentation: created.publicKeySpki)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: a.signature)
        XCTAssertTrue(key.isValidSignature(sig, for: a.authenticatorData + hash))
    }

    func testBase64Url() {
        let d = Data([0xfb, 0xff, 0xfe, 0x00, 0x01])
        let s = PasskeyLogic.b64url(d)
        XCTAssertEqual(s, "-__-AAE")
        XCTAssertEqual(PasskeyLogic.b64urlDecode(s), d)
        XCTAssertEqual(PasskeyLogic.b64urlDecode(s + "="), d)
        XCTAssertNil(PasskeyLogic.b64urlDecode("A"))
    }
}

/// What unlocking with the master password costs in memory (the AutoFill extension has a hard
/// limit): Argon2id with the default parameters (128 MiB, 3 passes).
final class KdfMemoryTests: XCTestCase {
    func testArgon2FootprintWithDefaultParams() throws {
        let baseline = MemoryStats.footprint()
        let accountId = try newId()
        let created = try createAccount(accountId: accountId, password: "correct horse battery staple", withSecretKey: false)
        let bundle = try JSON.parse(created.bundleJson)
        let kdf = (bundle["kdf"] ?? .null)
        XCTAssertEqual(kdf["memory_kib"]?.int, 128 * 1024)
        let before = MemoryStats.footprint()
        let start = Date()
        let master = try deriveMasterKeys(password: "correct horse battery staple", secretKey: nil, accountId: accountId, kdfJson: kdf.text, secretKeyRequired: false)
        _ = try master.unlock(bundleJson: created.bundleJson)
        let after = MemoryStats.footprint()
        let line = "KDF-MEMORY baseline=\(MemoryStats.mb(baseline.current)) baselinePeak=\(MemoryStats.mb(baseline.peak)) before=\(MemoryStats.mb(before.current)) peakBefore=\(MemoryStats.mb(before.peak)) after=\(MemoryStats.mb(after.current)) peakAfter=\(MemoryStats.mb(after.peak)) seconds=\(String(format: "%.2f", Date().timeIntervalSince(start)))"
        print(line)
        // Argon2id allocates its whole memory cost at once.
        XCTAssertGreaterThanOrEqual(after.peak, baseline.current + 120 * 1_048_576, line)
    }
}
