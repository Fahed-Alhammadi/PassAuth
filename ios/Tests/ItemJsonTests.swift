import PassAuthKit
import XCTest

/// The item JSON must stay compatible with the core and the web vault (web/src/lib/types.ts).
final class ItemJsonTests: XCTestCase {
    private let full = #"""
    {"format":2,"name":"GitHub","notes":"line 1\nline 2","favorite":true,"folder":"Work","tags":["dev"],
     "login":{"username":"octo","password":"s3cret","urls":[{"url":"https://github.com","match":"default"},{"url":"^https://gist\\.","match":"regex"}],
       "totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
       "passkeys":[{"credential_id":"Y3JlZA","rp_id":"github.com","rp_name":"GitHub","user_handle":"dQ","user_name":"octo","user_display_name":"Octo Cat",
         "algorithm":-7,"private_key":"cGs","counter":3,"discoverable":true,"created_at":1700000000}]},
     "card":null,"identity":null,"ssh_key":null,
     "fields":[{"name":"PIN","value":"1234","type":"hidden"},{"name":"VIP","value":"true","type":"boolean"}],
     "password_history":[{"password":"old","changed_at":1690000000}],
     "created_at":1680000000,"updated_at":1700000001}
    """#

    private func object(_ json: String) throws -> NSDictionary {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? NSDictionary)
    }

    func testRoundTripKeepsEveryField() throws {
        let item = try ItemCodec.decode(full)
        XCTAssertEqual(try object(full), try object(ItemCodec.encode(item)))
        XCTAssertEqual(item.kind, .login)
        XCTAssertEqual(item.login?.urls[1].match, .regex)
        XCTAssertEqual(item.siteHost, "github.com")
        XCTAssertEqual(item.fields[1].type, .boolean)
        XCTAssertEqual(item.login?.passkeys[0].counter, 3)
    }

    func testAllKindsRoundTrip() throws {
        for kind in ItemKind.allCases {
            var item = Item.empty(kind, now: 1_700_000_000)
            item.name = "x"
            let again = try ItemCodec.decode(ItemCodec.encode(item))
            XCTAssertEqual(item, again)
            XCTAssertEqual(again.kind, kind)
        }
    }

    func testNewItemsLeaveFormatToTheCoreAndWriteNulls() throws {
        let json = try object(ItemCodec.encode(Item.empty(.card, now: 1)))
        XCTAssertNil(json["format"], "format must be omitted, the core rejects null")
        XCTAssertEqual(json["login"] as? NSNull, NSNull())
        XCTAssertEqual(json["folder"] as? NSNull, NSNull())
        XCTAssertNotNil(json["ssh_key"])
        XCTAssertNotNil((json["card"] as? NSDictionary)?["cardholder_name"])
        let login = try object(ItemCodec.encode(Item.empty(.login, now: 1)))
        XCTAssertEqual((login["login"] as? NSDictionary)?["totp"] as? NSNull, NSNull())
    }

    func testToleratesMissingAndUnknownFields() throws {
        let item = try ItemCodec.decode(#"{"name":"Note","future_field":42,"login":{"username":"u","urls":[{"url":"a.com","match":"something_new"}]}}"#)
        XCTAssertEqual(item.name, "Note")
        XCTAssertEqual(item.login?.password, "")
        XCTAssertNil(item.login?.totp)
        XCTAssertEqual(item.login?.urls[0].match, .default)
        XCTAssertEqual(item.siteHost, "a.com")
    }

    func testNotesAreANoteKind() throws {
        XCTAssertEqual(try ItemCodec.decode(#"{"name":"n","notes":"hi"}"#).kind, .note)
    }
}
