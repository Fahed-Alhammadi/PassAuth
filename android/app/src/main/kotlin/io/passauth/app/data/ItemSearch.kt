package io.passauth.app.data

/**
 * The app's one item search, the same as the extension's popup (`extension/src/popup/search.ts`): every word
 * of the query (ANDed, case-insensitive) must appear in the item's name, user name, second line (card /
 * identity), any of its websites (full address, or its host without the scheme or "www."), its tags or its
 * folder. Results: items whose name (or a word of it) or a website's host starts with the query first, then
 * the rest in list order. Pure; tests in `ItemSearchTest`.
 */
object ItemSearch {
    private val SPACE = Regex("\\s+")
    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE)
    private val NAME_WORDS = Regex("[\\s._@/-]+")

    /** The query's words, in lower case. */
    fun words(query: String): List<String> = query.lowercase().split(SPACE).filter { it.isNotEmpty() }

    /** A website's address without its scheme and a leading "www.", in lower case. */
    fun host(url: String): String {
        val s = url.trim().replaceFirst(SCHEME, "")
        return (if (s.startsWith("www.", ignoreCase = true)) s.substring(4) else s).lowercase()
    }

    /** The second line of a card or identity (as the extension shows it): brand and last four digits, name and email. */
    fun subtitle(i: Item): String {
        i.card?.let { c ->
            val digits = c.number.filterNot { it.isWhitespace() }
            return listOf(c.brand, if (digits.length >= 4) "•••• ${digits.takeLast(4)}" else "").filter { it.isNotEmpty() }.joinToString(" ")
        }
        i.identity?.let { id ->
            val name = listOf(id.firstName, id.lastName).filter { it.isNotEmpty() }.joinToString(" ")
            return listOf(name, id.email).filter { it.isNotEmpty() }.joinToString(" · ")
        }
        return ""
    }

    /** The lower-case texts searched for [i]; [extra]: what the list shows for it besides. */
    private fun fields(i: Item, extra: List<String>): List<String> {
        val all = mutableListOf(i.name, i.login?.username.orEmpty(), subtitle(i), i.folder.orEmpty())
        i.login?.urls?.forEach { all += it.url; all += host(it.url) }
        all += i.tags
        all += extra
        return all.filter { it.isNotEmpty() }.map { it.lowercase() }
    }

    /** Whether [i] starts with the query: its name, a word of its name, or one of its websites' hosts. */
    private fun startsWith(i: Item, whole: String, first: String): Boolean {
        val name = i.name.lowercase()
        if (name.startsWith(whole)) return true
        if (name.split(NAME_WORDS).any { it.isNotEmpty() && it.startsWith(first) }) return true
        return i.login?.urls.orEmpty().any { it.url.isNotEmpty() && host(it.url).startsWith(first) }
    }

    /** Whether [i] matches every word of [query] (an empty query matches everything). */
    fun matches(i: Item, query: String, extra: List<String> = emptyList()): Boolean {
        val w = words(query)
        if (w.isEmpty()) return true
        val hay = fields(i, extra)
        return w.all { word -> hay.any { it.contains(word) } }
    }

    /**
     * [items] matching [query], best first (see above). [item]: the vault item of each element (null: only
     * [extra] is searched, as its name); [extra]: other texts shown for it (searched too).
     */
    fun <T> search(items: List<T>, query: String, extra: (T) -> List<String> = { emptyList() }, item: (T) -> Item?): List<T> {
        val w = words(query)
        val first = w.firstOrNull() ?: return items
        val whole = w.joinToString(" ")
        return items.mapIndexedNotNull { order, element ->
            val more = extra(element)
            val i = item(element) ?: Item(name = more.firstOrNull().orEmpty())
            val hay = fields(i, more)
            if (!w.all { word -> hay.any { it.contains(word) } }) return@mapIndexedNotNull null
            Triple(element, if (startsWith(i, whole, first)) 0 else 1, order)
        }.sortedWith(compareBy({ it.second }, { it.third })).map { it.first }
    }
}
