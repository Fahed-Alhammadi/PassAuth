import PassAuthKit
import XCTest

/// The write decision of the Background App Refresh cache update (`VaultRepository.offlineCopyUpdate`).
final class BackgroundRefreshTests: XCTestCase {
    private func sync(revision: Any? = 5, bundle: Any? = ["secret_key_enabled": false], vaults: Any? = [], items: Any? = []) -> Data {
        var o: [String: Any] = ["user": ["name": "Alex"]]
        if let revision { o["revision"] = revision }
        if let bundle { o["bundle"] = bundle }
        if let vaults { o["vaults"] = vaults }
        if let items { o["items"] = items }
        return try! JSONSerialization.data(withJSONObject: o)
    }

    func testWritesWhenNewerOrEqual() throws {
        let u = try XCTUnwrap(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 7), cached: sync(revision: 5)))
        XCTAssertEqual(u.revision, 7)
        XCTAssertEqual(try JSON.parse(XCTUnwrap(u.bundle)), ["secret_key_enabled": .bool(false)])
        XCTAssertEqual(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 5), cached: sync(revision: 5))?.revision, 5)
        XCTAssertEqual(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 1), cached: nil)?.revision, 1)
    }

    func testNeverDowngrades() {
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 4), cached: sync(revision: 5)))
    }

    func testUnreadableCacheIsReplaced() {
        XCTAssertEqual(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 3), cached: Data("garbage".utf8))?.revision, 3)
        XCTAssertEqual(VaultRepository.offlineCopyUpdate(fetched: sync(revision: 3), cached: sync(revision: nil))?.revision, 3)
    }

    func testRejectsInvalidBodies() {
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: Data("<html>".utf8), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: Data("{\"error\":\"unauthorized\"}".utf8), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(revision: nil), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(revision: "7"), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(bundle: nil), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(bundle: NSNull()), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(vaults: nil), cached: nil))
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(items: nil), cached: nil))
        // A malformed row (item without its data) isn't stored either.
        XCTAssertNil(VaultRepository.offlineCopyUpdate(fetched: sync(items: [["id": "i1", "vault_id": "v1"]]), cached: nil))
    }

    func testDefaultSettingAndOldStateFiles() throws {
        XCTAssertEqual(Settings().backgroundSyncMinutes, 120)
        let old = try JSONDecoder().decode(Settings.self, from: Data("{\"vaultTimeout\":\"min15\"}".utf8))
        XCTAssertEqual(old.backgroundSyncMinutes, 120)
        let off = try JSONDecoder().decode(Settings.self, from: Data("{\"backgroundSyncMinutes\":0}".utf8))
        XCTAssertEqual(off.backgroundSyncMinutes, 0)
    }
}
