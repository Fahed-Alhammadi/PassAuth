import PassAuthKit
import XCTest

/// The write decision of the Background App Refresh cache update without delta sync
/// (`DeltaSync.refresh`, the whole `/sync`; the delta path is in `DeltaSyncTests`).
final class BackgroundRefreshTests: XCTestCase {
    private func sync(revision: Any? = 5, bundle: Any? = ["secret_key_enabled": false], vaults: Any? = [], items: Any? = []) -> Data {
        var o: [String: Any] = ["user": ["name": "Alex"]]
        if let revision { o["revision"] = revision }
        if let bundle { o["bundle"] = bundle }
        if let vaults { o["vaults"] = vaults }
        if let items { o["items"] = items }
        return try! JSONSerialization.data(withJSONObject: o)
    }

    /// The refresh with `fetched` as the server's `/sync` and `cached` as the copy on the device.
    private func refresh(fetched: Data, cached: Data?) async throws -> DeltaSync.CacheRefresh {
        try await DeltaSync.refresh(cached: cached.flatMap(SyncSnapshot.decode), delta: false, trashSummary: false) { path in
            XCTAssertEqual(path, "/sync")
            return fetched
        }
    }

    private func written(_ r: DeltaSync.CacheRefresh) -> SyncSnapshot? {
        if case .write(let s) = r { return s }
        return nil
    }

    func testWritesWhenNewerOrEqual() async throws {
        let newer = try await refresh(fetched: sync(revision: 7), cached: sync(revision: 5))
        let u = try XCTUnwrap(written(newer))
        XCTAssertEqual(u.revision, 7)
        XCTAssertEqual(u.bundle, ["secret_key_enabled": .bool(false)])
        let same = try await refresh(fetched: sync(revision: 5), cached: sync(revision: 5))
        XCTAssertEqual(written(same)?.revision, 5)
        let first = try await refresh(fetched: sync(revision: 1), cached: nil)
        XCTAssertEqual(written(first)?.revision, 1)
    }

    func testNeverDowngrades() async throws {
        let r = try await refresh(fetched: sync(revision: 4), cached: sync(revision: 5))
        XCTAssertEqual(r, .keep)
    }

    func testUnreadableCacheIsReplaced() async throws {
        let garbage = try await refresh(fetched: sync(revision: 3), cached: Data("garbage".utf8))
        XCTAssertEqual(written(garbage)?.revision, 3)
        let noRevision = try await refresh(fetched: sync(revision: 3), cached: sync(revision: nil))
        XCTAssertEqual(written(noRevision)?.revision, 3)
    }

    func testRejectsInvalidBodies() async {
        let bad: [Data] = [
            Data("<html>".utf8),
            Data("{\"error\":\"unauthorized\"}".utf8),
            sync(revision: nil),
            sync(revision: "7"),
            sync(bundle: nil),
            sync(bundle: NSNull()),
            sync(vaults: nil),
            sync(items: nil),
            // A malformed row (a live item without its data) isn't stored either.
            sync(items: [["id": "i1", "vault_id": "v1"]]),
        ]
        for body in bad {
            do {
                _ = try await refresh(fetched: body, cached: nil)
                XCTFail("stored \(String(decoding: body, as: UTF8.self))")
            } catch {}
        }
    }

    func testDefaultSettingAndOldStateFiles() throws {
        XCTAssertEqual(Settings().backgroundSyncMinutes, 120)
        let old = try JSONDecoder().decode(Settings.self, from: Data("{\"vaultTimeout\":\"min15\"}".utf8))
        XCTAssertEqual(old.backgroundSyncMinutes, 120)
        let off = try JSONDecoder().decode(Settings.self, from: Data("{\"backgroundSyncMinutes\":0}".utf8))
        XCTAssertEqual(off.backgroundSyncMinutes, 0)
        // Account records written before the server feature list was kept.
        let account = try JSONDecoder().decode(AccountData.self, from: Data("{\"server\":\"https://a.example\",\"email\":\"a@example.com\",\"name\":\"\",\"lastSync\":0,\"biometric\":false}".utf8))
        XCTAssertNil(account.features)
    }
}
