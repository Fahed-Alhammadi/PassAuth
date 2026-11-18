import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// The golden vectors every client checks (testdata/vectors.json, generated from the Rust core's
/// WASM build by testdata/generate-vectors.mjs; copied into the test bundle), run through this
/// app's bindings of the same core and, wherever the app has one, its own wrapper (`UrlMatcher`,
/// `SaveLogic`, `PasskeyLogic`): host names, public suffixes and base domains, website matching,
/// the downgrade rule, regular-expression refusals, the save rule, passkey "Save in" targets and
/// RP ID checks (iOS and macOS check RP IDs themselves; the binding is checked all the same). Also
/// run by the macOS AutoFill extension's tests (desktop/macos/project.yml).
final class GoldenVectorTests: XCTestCase {
    private typealias Object = [String: Any]

    nonisolated(unsafe) private static let vectors: Object = {
        guard let url = Bundle(for: GoldenVectorTests.self).url(forResource: "vectors", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let object = try? JSONSerialization.jsonObject(with: data) as? Object
        else { return [:] }
        return object
    }()

    private static let sections = ["normalizeHost", "baseDomain", "publicSuffix", "urlMatch", "downgrade", "regexError", "savePlan", "passkeyTargets", "rpId"]

    private func cases(_ name: String) -> [Object] {
        Self.vectors[name] as? [Object] ?? []
    }

    /// A vector's optional string (`null` in JSON is NSNull).
    private func string(_ v: Any?) -> String? { v as? String }

    func testVectorsAreThere() {
        // A missing resource would make every check below pass on an empty list.
        XCTAssertEqual(Self.vectors["version"] as? Int, 2, "vectors.json format")
        for name in Self.sections {
            XCTAssertFalse(cases(name).isEmpty, "no \(name) vectors")
        }
        // The same Public Suffix List as the core these bindings were built from.
        XCTAssertEqual(Self.vectors["publicSuffixList"] as? String, publicSuffixListVersion())
    }

    func testHostsAndSites() {
        for c in cases("normalizeHost") {
            let host = c["host"] as? String ?? ""
            XCTAssertEqual(normalizeHost(host: host), string(c["expected"]), "normalizeHost(\(host))")
        }
        for c in cases("baseDomain") {
            let host = c["host"] as? String ?? ""
            XCTAssertEqual(UrlMatcher.baseDomain(host), c["expected"] as? String, "baseDomain(\(host))")
        }
        for c in cases("publicSuffix") {
            let host = c["host"] as? String ?? ""
            XCTAssertEqual(publicSuffix(host: host), c["expected"] as? String, "publicSuffix(\(host))")
        }
    }

    func testUrlMatching() {
        for c in cases("urlMatch") {
            let page = c["page"] as? String ?? "", url = c["url"] as? String ?? ""
            let match = c["match"] as? String ?? "", defaultMatch = c["defaultMatch"] as? String ?? ""
            // `allowRegex` false: a login in a vault somebody shared (its regular expressions never count).
            let allowRegex = c["allowRegex"] as? Bool ?? true
            let want = c["expected"] as? Bool
            let label = "\(match)/\(defaultMatch) \(allowRegex ? "own" : "shared") \(page) vs \(url) (\(c["note"] ?? ""))"
            if let m = UrlMatch(rawValue: match), let d = UrlMatch(rawValue: defaultMatch) {
                // The app's wrappers: one website, and the same as a login's only website.
                XCTAssertEqual(UrlMatcher.matches(page, LoginUrl(url: url, match: m), fallback: d, allowRegex: allowRegex), want, label)
                let login = Login(username: "", password: "", urls: [LoginUrl(url: url, match: m)])
                XCTAssertEqual(UrlMatcher.matchesAny(page, login, fallback: d, allowRegex: allowRegex), want, "matchesAny " + label)
            } else {
                // Match types the app's items never carry (an unknown one reads as "default"):
                // the binding's string rules.
                XCTAssertEqual(matchesUrl(page: page, url: url, matchType: match, defaultMatch: defaultMatch, allowRegex: allowRegex), want, label)
            }
        }
        XCTAssertTrue(cases("urlMatch").contains { $0["allowRegex"] as? Bool == false }, "no shared-vault cases")
        for c in cases("downgrade") {
            let page = c["page"] as? String ?? "", url = c["url"] as? String ?? ""
            let match = UrlMatch(rawValue: c["match"] as? String ?? "") ?? .domain
            XCTAssertEqual(UrlMatcher.downgrade(page, LoginUrl(url: url, match: match)), c["expected"] as? Bool, "downgrade \(page) vs \(url) (\(c["note"] ?? ""))")
        }
        for c in cases("regexError") {
            let pattern = c["pattern"] as? String ?? ""
            XCTAssertEqual(UrlMatcher.regexError(pattern), string(c["expected"]), "regexError \(pattern.prefix(40))")
        }
    }

    // MARK: Save rule

    private static let page = "https://example.com/login"

    /// The vault a vector's logins live in: the user's own vault, shared vaults with write access
    /// and view-only ones, each login saved for `https://example.com` (so all of them match the page).
    private func saveVault(_ candidates: [Object]) -> VaultData {
        var v = VaultData()
        v.vaults = [VaultInfo(id: "personal", name: "Personal", role: .owner)]
        for o in candidates {
            let id = o["id"] as? String ?? ""
            let vaultId = vaultIdOf(o)
            if !v.vaults.contains(where: { $0.id == vaultId }) {
                v.vaults.append(VaultInfo(id: vaultId, name: o["vault"] as? String ?? "", role: (o["writable"] as? Bool ?? false) ? .write : .read, keyKind: "sealed"))
            }
            let login = Login(username: o["username"] as? String ?? "", password: o["password"] as? String ?? "", urls: [LoginUrl(url: "https://example.com", match: .default)])
            v.entries.append(Entry(id: id, item: Item(name: o["name"] as? String ?? "", login: login), vaultId: vaultId, revision: 1,
                                   enc: EncryptedItem(id: id, vaultId: vaultId, key: "", data: ""), deletedAt: nil))
        }
        return v
    }

    private func vaultIdOf(_ o: Object) -> String {
        if o["personal"] as? Bool == true { return "personal" }
        return (o["writable"] as? Bool == true ? "shared-" : "ro-") + (o["vault"] as? String ?? "")
    }

    /// How a shared vault is named in the vectors: its name, or the core's label for one without.
    private func vaultLabel(_ e: Entry, in v: VaultData) -> String {
        guard let name = v.sharedVaultName(e) else { return "-" }
        return name.isEmpty ? "Shared vault" : name
    }

    private func describe(_ plan: SaveLogic.Plan) -> String {
        switch plan {
        case .noPassword, .unchanged: "none"
        case .create: "create"
        case .update(let e, let why): "update \(why) \(e.id)"
        }
    }

    func testSavePlan() {
        for c in cases("savePlan") {
            let name = c["name"] as? String ?? ""
            let candidates = c["candidates"] as? [Object] ?? []
            let user = c["typedUser"] as? String ?? "", password = c["password"] as? String ?? ""
            let want = c["expected"] as? Object ?? [:]
            let v = saveVault(candidates)
            let plan = SaveLogic.plan(page: Self.page, username: user, password: password, vault: v, defaultMatch: .domain)
            let action = want["action"] as? String ?? ""
            let wanted = action == "update" ? "update \(want["reason"] ?? "") \(want["target"] ?? "")" : action
            XCTAssertEqual(describe(plan), wanted, name)
            // "Save in": the targets in order, a shared one labelled with its vault (none when
            // there is nothing to save).
            let targets = SaveLogic.targets(page: Self.page, username: user, password: password, vault: v, defaultMatch: .domain)
            let got = targets.map { [$0.id, vaultLabel($0, in: v)] }
            let wantTargets = (want["targets"] as? [Object] ?? []).map { [$0["id"] as? String ?? "", $0["vault"] as? String ?? "-"] }
            XCTAssertEqual(got, wantTargets, "\(name): targets")
            guard action != "none" else { continue }
            // Only what was offered is accepted as a choice; "New login" always.
            for o in candidates {
                let id = o["id"] as? String ?? ""
                let accepted = SaveLogic.plan(target: id, page: Self.page, username: user, password: password, vault: v, defaultMatch: .domain) != nil
                XCTAssertEqual(accepted, wantTargets.contains { $0[0] == id }, "\(name): choice \(id)")
            }
            guard case .create? = SaveLogic.plan(target: SaveLogic.newLogin, page: Self.page, username: user, password: password, vault: v, defaultMatch: .domain) else {
                return XCTFail("\(name): New login refused")
            }
        }
    }

    // MARK: Passkey "Save in"

    func testPasskeyTargets() {
        for c in cases("passkeyTargets") {
            let name = c["name"] as? String ?? ""
            let logins = c["logins"] as? [Object] ?? []
            var v = VaultData()
            v.vaults = [VaultInfo(id: "personal", name: "Personal", role: .owner)]
            for o in logins {
                let id = o["id"] as? String ?? ""
                let vaultId = vaultIdOf(o)
                if !v.vaults.contains(where: { $0.id == vaultId }) {
                    v.vaults.append(VaultInfo(id: vaultId, name: o["vault"] as? String ?? "", role: (o["writable"] as? Bool ?? false) ? .write : .read, keyKind: "sealed"))
                }
                let urls = (o["urls"] as? [String] ?? []).map { LoginUrl(url: $0, match: .default) }
                let login = Login(username: o["username"] as? String ?? "", password: "pw", urls: urls)
                v.entries.append(Entry(id: id, item: Item(name: o["name"] as? String ?? "", login: login), vaultId: vaultId, revision: 1,
                                       enc: EncryptedItem(id: id, vaultId: vaultId, key: "", data: ""), deletedAt: nil))
            }
            let host = c["host"] as? String ?? "", rpId = c["rpId"] as? String ?? ""
            let choices = PasskeyLogic.saveChoices(v, rpId: rpId, userName: c["userName"] as? String ?? "", host: host, displayName: c["displayName"] as? String ?? "")
            let got = choices.map { "\($0.id) \($0.preferred) \(vaultLabel($0.entry, in: v))" }
            let wanted = (c["expected"] as? [Object] ?? []).map { "\($0["id"] ?? "") \($0["preferred"] as? Bool ?? false) \($0["vault"] as? String ?? "-")" }
            XCTAssertEqual(got, wanted, name)
            XCTAssertEqual(PasskeyLogic.defaultTarget(choices), c["expectedDefault"] as? String, "\(name): default")
        }
    }

    // MARK: RP ID

    /// The `SecurityError` message the core gives (the binding's flat error carries it).
    private func message(_ e: RpIdError) -> String {
        switch e {
        case .InvalidOrigin(let m), .InsecureOrigin(let m), .OriginNotDomain(let m), .InvalidRpId(let m), .NotRegistrableSuffix(let m): m
        }
    }

    func testRpIdThroughTheBinding() {
        for c in cases("rpId") {
            let origin = c["origin"] as? String ?? "", requested = string(c["requested"])
            let label = "\(origin) \(requested ?? "nil") (\(c["note"] ?? ""))"
            do {
                // Called outside the assertion: XCTAssert would record a throw as a failure itself.
                let rp = try effectiveRpId(requestedRpId: requested, origin: origin)
                XCTAssertEqual(rp, string(c["expected"]), label)
            } catch let e as RpIdError {
                XCTAssertNil(string(c["expected"]), label)
                XCTAssertEqual(c["error"] as? String, "SecurityError", label)
                XCTAssertEqual(message(e), c["message"] as? String, label)
            } catch {
                XCTFail("\(label): \(error)")
            }
        }
    }

    // MARK: Vault manifests

    /// `vaultManifest`: every verdict of a check and every kind of write, through the binding
    /// with the fixture's vault key, and through the app's own wrapper (`VaultManifest`) where it
    /// builds the rows itself.
    func testVaultManifestThroughTheBinding() throws {
        let m = try XCTUnwrap(Self.vectors["vaultManifest"] as? Object, "no vaultManifest vectors")
        let vaultId = m["vaultId"] as? String ?? ""
        let epoch = UInt64(m["keyEpoch"] as? Int ?? 0)
        var b64 = (m["sessionBytes"] as? String ?? "").replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        let bytes = try XCTUnwrap(Data(base64Encoded: b64))
        let account = try accountFromSessionBytes(accountId: m["accountId"] as? String ?? "", bytes: bytes)
        let key = try account.openVaultKey(vaultId: vaultId, wrapped: m["wrappedKey"] as? String ?? "", kind: "account", keyEpoch: epoch, legacyAllowed: false)
        let items = m["items"] as? Object ?? [:]
        let sealed = m["sealed"] as? Object ?? [:]
        func text(_ any: Any?) throws -> String {
            String(decoding: try JSONSerialization.data(withJSONObject: any ?? [], options: [.withoutEscapingSlashes]), as: UTF8.self)
        }
        func number(_ any: Any?) -> UInt64? { (any as? NSNumber)?.uint64Value }

        let checks = m["checks"] as? [Object] ?? []
        XCTAssertGreaterThan(checks.count, 20)
        for (i, c) in checks.enumerated() {
            let name = "check \(i) (\(c["items"] ?? ""), \(c["sealed"] ?? "no manifest"))"
            let seq = number(c["manifestSeq"]) ?? 0
            let text0 = (c["sealed"] as? String).flatMap { sealed[$0] as? String }
            let remembered = number(c["remembered"])
            let rows = items[c["items"] as? String ?? ""]
            let expected = c["expected"] as? Object ?? [:]
            let got = try key.manifestVerify(vaultId: vaultId, keyEpoch: epoch, manifestSeq: seq, sealed: text0, remembered: remembered, itemsJson: try text(rows))
            XCTAssertEqual(got.status, expected["status"] as? String, name)
            XCTAssertEqual(got.version, number(expected["version"]), name)
            XCTAssertEqual(got.live, number(expected["live"]), name)
            XCTAssertEqual(got.trashed, number(expected["trashed"]), name)
            // The app's wrapper, from rows as it holds them (the copy's `SyncItem`).
            if let decoded = try? JSONDecoder().decode([SyncItem].self, from: JSONSerialization.data(withJSONObject: rows ?? [])) {
                let row = SyncVault(id: vaultId, keyEpoch: Int64(epoch), manifest: text0, manifestSeq: Int64(seq))
                let mine = VaultManifest.verify(row, key: key, remembered: remembered, rows: decoded)
                XCTAssertEqual(mine.status.rawValue, expected["status"] as? String, "\(name) through VaultManifest")
                XCTAssertEqual(mine.version, number(expected["version"]), "\(name) through VaultManifest")
            }
        }

        let version = number(m["version"]) ?? 0
        let current = try XCTUnwrap(sealed["current"] as? String)
        let writes = m["writes"] as? [Object] ?? []
        XCTAssertGreaterThanOrEqual(writes.count, 8)
        for w in writes {
            let name = w["name"] as? String ?? ""
            let expected = w["expected"] as? Object ?? [:]
            let next = try key.manifestNext(vaultId: vaultId, keyEpoch: epoch, manifestSeq: version, sealed: current,
                                            removedJson: try text(w["removed"]), addedJson: try text(w["added"]))
            XCTAssertEqual(next.seq, number(expected["seq"]), name)
            let after = try key.manifestVerify(vaultId: vaultId, keyEpoch: epoch, manifestSeq: next.seq, sealed: next.sealed, remembered: version,
                                               itemsJson: try text(w["after"]))
            XCTAssertEqual(after.status, "ok", name)
            XCTAssertEqual(after.live, number(expected["live"]), name)
            XCTAssertEqual(after.trashed, number(expected["trashed"]), name)
        }
        // The hash of a row's data, as the server sends it for rows without data.
        for t in m["terms"] as? [Object] ?? [] {
            guard let id = t["id"] as? String, let row = (items["full"] as? [Object])?.first(where: { $0["id"] as? String == id }),
                  let data = row["data"] as? String else { continue }
            XCTAssertEqual(manifestDataHash(data: data), t["dataSha256"] as? String, id)
        }
    }
}
