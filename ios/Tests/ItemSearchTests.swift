import PassAuthCore
import PassAuthKit
import XCTest

/// `ItemSearch`: the cases of the extension's `test/search.test.ts` (minus the current page's logins, which the
/// phones' lists don't have), plus a login found by its second website.
final class ItemSearchTests: XCTestCase {
    private func item(_ name: String, user: String = "", urls: [String] = [], tags: [String] = [], folder: String? = nil,
                      card: Card? = nil, identity: Identity? = nil, note: Bool = false) -> Item {
        var i = Item(name: name, folder: folder,
                     login: note || card != nil || identity != nil ? nil : Login(username: user, urls: urls.map { LoginUrl(url: $0) }),
                     card: card, identity: identity)
        i.tags = tags
        return i
    }

    private lazy var items: [(String, Item)] = [
        ("a", item("Bank of Example", user: "alex", urls: ["https://bank.example"], tags: ["money"], folder: "Finance")),
        ("b", item("GitHub", user: "alex-dev", urls: ["https://github.com/login"])),
        ("c", item("Work mail", user: "alex@work.test", urls: ["https://mail.work.test"], folder: "Work")),
        ("d", item("Wifi", tags: ["home"], note: true)),
    ]

    private func found(_ q: String, in list: [(String, Item)]? = nil) -> [String] {
        ItemSearch.search(list ?? items, q, item: \.1).map(\.0)
    }

    func testEmptyQueryKeepsEveryItemInOrder() {
        XCTAssertEqual(found("   "), ["a", "b", "c", "d"])
        XCTAssertEqual(ItemSearch.words("  Foo   bar "), ["foo", "bar"])
    }

    func testLooksInNameUserNameEveryWebsiteTagsAndFolder() {
        XCTAssertEqual(found("github"), ["b"])
        XCTAssertEqual(found("alex-dev"), ["b"])
        XCTAssertEqual(found("mail.work"), ["c"])
        XCTAssertEqual(found("money"), ["a"])
        XCTAssertEqual(found("finance"), ["a"])
        XCTAssertEqual(found("HOME"), ["d"])
    }

    func testEveryWordMustMatch() {
        XCTAssertEqual(found("alex work"), ["c"])
        XCTAssertEqual(found("alex finance"), ["a"])
        XCTAssertEqual(found("alex nothing"), [])
    }

    func testNameAndWebsitePrefixesFirstThenListOrder() {
        XCTAssertEqual(found("alex"), ["a", "b", "c"])
        XCTAssertEqual(found("m"), ["c", "a", "b", "d"])
        // A website's host (without "www.") counts like a name: both start with "git", so list order decides.
        let list = [items[0], ("x", item("Code", urls: ["https://www.gitlab.example"])), items[1]]
        XCTAssertEqual(found("git", in: list), ["x", "b"])
    }

    func testEveryWebsiteCountsNotOnlyTheFirst() {
        let list = [
            ("other", item("Other", urls: ["https://example.com"])),
            ("login", item("Login", user: "me", urls: ["https://account.example", "https://www.samsung.com/signin"])),
        ]
        XCTAssertEqual(found("samsung.com", in: list), ["login"])
        XCTAssertEqual(found("Samsung", in: list), ["login"])
        XCTAssertEqual(found("SAMSUNG.COM/SIGNIN", in: list), ["login"])
        // Its host starts with the query: ranked before an item that only contains it.
        let ranked = [("note", item("My samsung notes", note: true)), list[1]]
        XCTAssertEqual(found("samsung", in: ranked), ["note", "login"])
        XCTAssertEqual(found("sam", in: [("x", item("Wisam")), list[1]]), ["login", "x"])
    }

    func testCardAndIdentitySecondLine() {
        var card = Card()
        card.brand = "Visa"
        card.number = "4111 1111 1111 1234"
        var identity = Identity()
        identity.firstName = "Alex"
        identity.lastName = "Morgan"
        identity.email = "alex@example.com"
        let list = [("card", item("Travel card", card: card)), ("id", item("Me", identity: identity))]
        XCTAssertEqual(found("visa 1234", in: list), ["card"])
        XCTAssertEqual(found("morgan", in: list), ["id"])
    }

    func testIdnHostsAsStored() {
        let list = [("idn", item("Shop", urls: ["https://xn--bcher-kva.example"])), ("u", item("Bücher", urls: ["https://bücher.example"]))]
        XCTAssertEqual(found("xn--bcher", in: list), ["idn"])
        XCTAssertEqual(found("BÜCHER.example", in: list), ["u"])
    }

    func testAutofillSearchUsesIt() {
        func entry(_ id: String, _ i: Item) -> Entry {
            Entry(id: id, item: i, vaultId: "v", revision: 1, enc: EncryptedItem(id: id, vaultId: "v", key: "", data: ""), deletedAt: nil)
        }
        let entries = [entry("n", item("Note", note: true)), entry("o", item("Other", urls: ["https://example.com"])),
                       entry("l", item("Login", urls: ["https://account.example", "https://samsung.com"]))]
        XCTAssertEqual(AutofillMatcher.search("samsung.com", entries).map(\.id), ["l"])
        XCTAssertEqual(AutofillMatcher.search("", entries).map(\.id), ["o", "l"])
    }
}
