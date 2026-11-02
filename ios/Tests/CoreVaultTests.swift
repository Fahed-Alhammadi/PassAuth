import PassAuthCore
import PassAuthKit
import XCTest

/// The Swift bindings drive the Rust core end to end: account, vault key, item encryption.
final class CoreVaultTests: XCTestCase {
    func testItemSurvivesCoreEncryption() throws {
        let created = try createAccount(accountId: try newId(), password: "correct horse battery staple", withSecretKey: false)
        let vaultId = try newId()
        let nv = try created.account.newVaultKey(vaultId: vaultId)
        var item = Item.empty(.login, now: 1_700_000_000)
        item.name = "Example"
        item.login?.username = "alice"
        item.login?.password = "s3cret"
        let id = try newId()
        let enc = try nv.key.encryptItem(itemJson: ItemCodec.encode(item), id: id, vaultId: vaultId)
        let back = try ItemCodec.decode(try nv.key.decryptItem(encrypted: enc))
        XCTAssertEqual(back.name, "Example")
        XCTAssertEqual(back.login, item.login)
        XCTAssertNotNil(back.format, "the core stamps the format")
        // Session bytes restore the same account (biometric unlock and vault timeout "never").
        let bytes = created.account.toSessionBytes()
        XCTAssertEqual(bytes.count, 64)
        let restored = try accountFromSessionBytes(accountId: "x", bytes: bytes)
        XCTAssertEqual(restored.publicKey(), created.account.publicKey())
    }

    func testGenerators() throws {
        let p = try generatePassword(optionsJson: #"{"length":24,"uppercase":true,"lowercase":true,"digits":true,"symbols":false,"avoid_ambiguous":false}"#)
        XCTAssertEqual(p.count, 24)
        XCTAssertTrue(p.allSatisfy { $0.isLetter || $0.isNumber })
        let words = try generatePassphrase(optionsJson: #"{"words":4,"separator":"-","capitalize":true,"include_number":false}"#)
        XCTAssertEqual(words.split(separator: "-").count, 4)
        XCTAssertGreaterThan(estimateBits(password: p), 100)
    }
}
