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

    /// Fields a newer app adds inside a login, website, passkey, card, identity, SSH key, custom
    /// field or password history entry survive decode → edit → encode here.
    func testUnknownNestedFieldsSurviveAnEdit() throws {
        let json = #"""
        {"format":2,"name":"All","notes":"","favorite":false,"folder":null,"tags":[],
         "login":{"username":"u","password":"p","urls":[{"url":"https://a.example","match":"host","label":"Work"}],"totp":null,
           "passkeys":[{"credential_id":"Y3JlZA","rp_id":"a.example","rp_name":"A","user_handle":"dQ","user_name":"u","user_display_name":"U",
             "algorithm":-7,"private_key":"cGs","counter":0,"discoverable":true,"created_at":1,"backup_state":true}],
           "autofill_on_load":{"enabled":true}},
         "card":{"cardholder_name":"A","brand":"","number":"4111","exp_month":"","exp_year":"","code":"","pin":"1234"},
         "identity":{"title":"","first_name":"Ann","middle_name":"","last_name":"","company":"","email":"","phone":"","address1":"","address2":"",
           "city":"","state":"","postal_code":"","country":"","username":"","ssn":"","passport_number":"","license_number":"","birthday":"2000-01-01"},
         "ssh_key":{"private_key":"k","public_key":"p","fingerprint":"f","comment":"laptop"},
         "fields":[{"name":"PIN","value":"1","type":"hidden","linked_to":"password"}],
         "password_history":[{"password":"old","changed_at":5,"changed_by":"web"}],
         "attachments":{"v":2,"list":[]},
         "created_at":1,"updated_at":2,"color":"blue"}
        """#
        var item = try ItemCodec.decode(json)
        XCTAssertEqual(item.login?.urls[0].extra["label"], "Work")
        XCTAssertEqual(item.card?.extra["pin"], "1234")
        XCTAssertNil(item.attachments)
        XCTAssertEqual(AttachmentList.read(item), [])
        // An edit to known fields, everywhere.
        item.name = "Edited"
        item.login?.password = "p2"
        item.login?.urls[0].url = "https://b.example"
        item.login?.passkeys[0].counter = 9
        item.card?.number = "4242"
        item.identity?.firstName = "Bea"
        item.sshKey?.fingerprint = "g"
        item.fields[0].value = "2"
        item.passwordHistory[0].password = "older"
        let out = try object(ItemCodec.encode(item))
        let login = try XCTUnwrap(out["login"] as? NSDictionary)
        XCTAssertEqual((login["urls"] as? [NSDictionary])?.first?["label"] as? String, "Work")
        XCTAssertEqual((login["urls"] as? [NSDictionary])?.first?["url"] as? String, "https://b.example")
        XCTAssertEqual((login["passkeys"] as? [NSDictionary])?.first?["backup_state"] as? Bool, true)
        XCTAssertEqual((login["passkeys"] as? [NSDictionary])?.first?["counter"] as? Int, 9)
        XCTAssertEqual((login["autofill_on_load"] as? NSDictionary)?["enabled"] as? Bool, true)
        XCTAssertEqual((out["card"] as? NSDictionary)?["pin"] as? String, "1234")
        XCTAssertEqual((out["identity"] as? NSDictionary)?["birthday"] as? String, "2000-01-01")
        XCTAssertEqual((out["ssh_key"] as? NSDictionary)?["comment"] as? String, "laptop")
        XCTAssertEqual((out["fields"] as? [NSDictionary])?.first?["linked_to"] as? String, "password")
        XCTAssertEqual((out["password_history"] as? [NSDictionary])?.first?["changed_by"] as? String, "web")
        XCTAssertEqual((out["attachments"] as? NSDictionary)?["v"] as? Int, 2)
        XCTAssertEqual(out["color"] as? String, "blue")
        // Unchanged, it comes back exactly as written.
        XCTAssertEqual(try object(json), try object(ItemCodec.encode(try ItemCodec.decode(json))))
        // A known key is never written twice from `extra`.
        var odd = try ItemCodec.decode(json)
        odd.card?.extra["number"] = "0000"
        XCTAssertEqual((try object(ItemCodec.encode(odd))["card"] as? NSDictionary)?["number"] as? String, "4111")
        // An export leaves an attachments value of any shape out.
        XCTAssertNil(try object(ItemCodec.encode(AttachmentList.strip(item)))["attachments"])
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
