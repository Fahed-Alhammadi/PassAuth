package io.passauth.app.data

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [ItemSearch]: the cases of the extension's `test/search.test.ts` (minus the current page's logins, which the
 * phone's lists don't have), plus a login found by its second website.
 */
class ItemSearchTest {
    private fun login(name: String, user: String = "", urls: List<String> = emptyList(), tags: List<String> = emptyList(), folder: String? = null) =
        Item(name = name, folder = folder, tags = tags, login = Login(username = user, urls = urls.map { LoginUrl(url = it) }))

    private val items = listOf(
        "a" to login("Bank of Example", "alex", listOf("https://bank.example"), listOf("money"), "Finance"),
        "b" to login("GitHub", "alex-dev", listOf("https://github.com/login")),
        "c" to login("Work mail", "alex@work.test", listOf("https://mail.work.test"), folder = "Work"),
        "d" to Item(name = "Wifi", tags = listOf("home")),
    )

    private fun found(q: String, list: List<Pair<String, Item>> = items) = ItemSearch.search(list, q) { it.second }.map { it.first }

    @Test
    fun anEmptyQueryKeepsEveryItemInItsOrder() {
        assertEquals(listOf("a", "b", "c", "d"), found("   "))
        assertEquals(listOf("foo", "bar"), ItemSearch.words("  Foo   bar "))
    }

    @Test
    fun looksInTheNameUserNameEveryWebsiteTagsAndFolder() {
        assertEquals(listOf("b"), found("github"))
        assertEquals(listOf("b"), found("alex-dev"))
        assertEquals(listOf("c"), found("mail.work"))
        assertEquals(listOf("a"), found("money"))
        assertEquals(listOf("a"), found("finance"))
        assertEquals(listOf("d"), found("HOME"))
    }

    @Test
    fun everyWordMustMatch() {
        assertEquals(listOf("c"), found("alex work"))
        assertEquals(listOf("a"), found("alex finance"))
        assertEquals(emptyList<String>(), found("alex nothing"))
    }

    @Test
    fun nameAndWebsitePrefixesFirstThenTheListOrder() {
        assertEquals(listOf("a", "b", "c"), found("alex"))
        assertEquals(listOf("c", "a", "b", "d"), found("m"))
        // A website's host (without "www.") counts like a name: both start with "git", so list order decides.
        assertEquals(listOf("x", "b"), found("git", listOf(items[0], "x" to login("Code", urls = listOf("https://www.gitlab.example")), items[1])))
    }

    @Test
    fun everyWebsiteCountsNotOnlyTheFirst() {
        val samsung = "login" to login("Login", "me", listOf("https://account.example", "https://www.samsung.com/signin"))
        val list = listOf("other" to login("Other", urls = listOf("https://example.com")), samsung)
        assertEquals(listOf("login"), found("samsung.com", list))
        assertEquals(listOf("login"), found("Samsung", list))
        assertEquals(listOf("login"), found("SAMSUNG.COM/SIGNIN", list))
        // Its host starts with the query: ranked before an item that only contains it.
        assertEquals(listOf("note", "login"), found("samsung", listOf("note" to Item(name = "My samsung notes"), samsung)))
        assertEquals(listOf("login", "x"), found("sam", listOf("x" to login("Wisam"), samsung)))
    }

    @Test
    fun cardAndIdentitySecondLine() {
        val list = listOf(
            "card" to Item(name = "Travel card", card = Card(brand = "Visa", number = "4111 1111 1111 1234")),
            "id" to Item(name = "Me", identity = Identity(firstName = "Alex", lastName = "Morgan", email = "alex@example.com")),
        )
        assertEquals(listOf("card"), found("visa 1234", list))
        assertEquals(listOf("id"), found("morgan", list))
    }

    @Test
    fun idnHostsAsStored() {
        val list = listOf("idn" to login("Shop", urls = listOf("https://xn--bcher-kva.example")), "u" to login("Bücher", urls = listOf("https://bücher.example")))
        assertEquals(listOf("idn"), found("xn--bcher", list))
        assertEquals(listOf("u"), found("BÜCHER.example", list))
    }

    @Test
    fun elementsWithoutAnItemSearchTheirTexts() {
        data class Choice(val title: String, val detail: String, val item: Item?)
        val choices = listOf(
            Choice("New login", "samsung.com", null),
            Choice("Login", "me", login("Login", "me", listOf("https://account.example", "https://samsung.com"))),
        )
        val got = ItemSearch.search(choices, "samsung.com", extra = { listOf(it.title, it.detail) }) { it.item }
        assertEquals(listOf("Login", "New login"), got.map { it.title }) // its host starts with the query
        assertEquals(listOf("Login"), ItemSearch.search(choices, "account") { it.item }.map { it.title })
    }
}
