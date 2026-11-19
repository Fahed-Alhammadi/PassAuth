package io.passauth.app.autofill

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StructureParserTest {
    private class N(
        override val webDomain: String? = null,
        override val webScheme: String? = null,
        override val field: FieldInfo<String>? = null,
        override val children: List<StructureNode<String>> = emptyList(),
        override val visible: Boolean = true,
    ) : StructureNode<String>

    private val text = InputType.TYPE_CLASS_TEXT
    private val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD

    private fun native(id: String, type: Int = text, entry: String? = null, hint: String? = null) =
        N(field = FieldInfo(id, inputType = type, idEntry = entry, hint = hint))

    private fun web(id: String, vararg attrs: Pair<String, String>) = N(field = FieldInfo(id, htmlTag = "input", htmlAttrs = mapOf(*attrs)))

    @Test
    fun compatibilityModeTakesTheDomainFromTheAddressBar() {
        // Android set the domain on the address bar; the page's fields have none of their own.
        val root = N(
            children = listOf(
                N(webDomain = "accounts.example.com", webScheme = "https", field = FieldInfo("bar", inputType = text, idEntry = "url_bar", value = "accounts.example.com")),
                N(children = listOf(native("user", hint = "Email"), native("pw", password))),
            ),
        )
        val c = StructureParser.collect(listOf(root))
        assertEquals("accounts.example.com", c.webDomain)
        assertEquals("https", c.webScheme)
        // The address bar is never a login field.
        assertEquals(listOf("user", "pw"), c.fields.map { it.id })
        val form = FieldClassifier.parse(c.fields)
        assertEquals("user", form.username?.id)
        assertEquals(listOf("pw"), form.passwords.map { it.id })
    }

    @Test
    fun addressBarsThatDisagreeGiveNoDomain() {
        val root = N(
            children = listOf(
                N(webDomain = "a.example", field = FieldInfo("bar1")),
                N(webDomain = "b.example", field = FieldInfo("bar2")),
                native("pw", password),
            ),
        )
        val c = StructureParser.collect(listOf(root))
        assertNull(c.webDomain)
        assertEquals(listOf("pw"), c.fields.map { it.id })
    }

    @Test
    fun nativeWebContentWinsAndKeepsOnlyItsFields() {
        val page = N(webDomain = "example.com", webScheme = "https", children = listOf(web("u", "type" to "email"), web("p", "type" to "password")))
        val frame = N(webDomain = "ads.example.net", children = listOf(web("x", "type" to "password")))
        val root = N(children = listOf(N(webDomain = "example.com", field = FieldInfo("bar")), page, frame))
        val c = StructureParser.collect(listOf(root))
        assertEquals("example.com", c.webDomain)
        assertEquals(listOf("u", "p"), c.fields.map { it.id })
    }

    @Test
    fun hiddenNodesAndAppsWithoutWebContent() {
        val root = N(children = listOf(native("u", entry = "username"), N(visible = false, children = listOf(native("hidden", password))), native("p", password)))
        val c = StructureParser.collect(listOf(root))
        assertNull(c.webDomain)
        assertEquals(listOf("u", "p"), c.fields.map { it.id })
    }

    @Test
    fun addressBarIdsAreNeverLoginFields() {
        assertEquals(FieldKind.Other, FieldClassifier.classify(FieldInfo("b", inputType = text, idEntry = "url_bar", hint = "Search or type web address")))
        assertEquals(FieldKind.Other, FieldClassifier.classify(FieldInfo("b", inputType = text, idEntry = "mozac_browser_toolbar_url_view")))
        // Without a password field nothing else counts as a user name either.
        val form = FieldClassifier.parse(listOf(FieldInfo("b", inputType = text, idEntry = "location_bar_edit_text"), FieldInfo("p", inputType = password)))
        assertNull(form.username)
    }
}
