package io.passauth.app

import io.passauth.app.data.AppJson
import io.passauth.app.data.FieldType
import io.passauth.app.data.Item
import io.passauth.app.data.ItemCodec
import io.passauth.app.data.ItemKind
import io.passauth.app.data.UrlMatch
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The item JSON must stay byte-for-byte compatible with the core and the web vault (types.ts). */
class ItemJsonTest {
    private val full = """
        {"format":2,"name":"GitHub","notes":"line 1\nline 2","favorite":true,"folder":"Work","tags":["dev"],
         "login":{"username":"octo","password":"s3cret","urls":[{"url":"https://github.com","match":"default"},{"url":"^https://gist\\.","match":"regex"}],
           "totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
           "passkeys":[{"credential_id":"Y3JlZA","rp_id":"github.com","rp_name":"GitHub","user_handle":"dQ","user_name":"octo","user_display_name":"Octo Cat",
             "algorithm":-7,"private_key":"cGs","counter":3,"discoverable":true,"created_at":1700000000}]},
         "card":null,"identity":null,"ssh_key":null,
         "fields":[{"name":"PIN","value":"1234","type":"hidden"},{"name":"VIP","value":"true","type":"boolean"}],
         "password_history":[{"password":"old","changed_at":1690000000}],
         "created_at":1680000000,"updated_at":1700000001}
    """.trimIndent()

    @Test
    fun roundTripKeepsEveryField() {
        val item = ItemCodec.decode(full)
        assertEquals(AppJson.parseToJsonElement(full), AppJson.parseToJsonElement(ItemCodec.encode(item)))
        assertEquals(ItemKind.Login, item.kind)
        assertEquals(UrlMatch.Regex, item.login!!.urls[1].match)
        assertEquals("github.com", item.siteHost)
        assertEquals(FieldType.Boolean, item.fields[1].type)
        assertEquals(3L, item.login.passkeys[0].counter)
    }

    @Test
    fun allKindsRoundTrip() {
        for (kind in ItemKind.entries) {
            val item = Item.empty(kind, 1700000000).copy(name = "x")
            val again = ItemCodec.decode(ItemCodec.encode(item))
            assertEquals(item, again)
            assertEquals(kind, again.kind)
        }
    }

    @Test
    fun newItemsLeaveFormatToTheCoreAndWriteNulls() {
        val json = AppJson.parseToJsonElement(ItemCodec.encode(Item.empty(ItemKind.Card, 1))).jsonObject
        assertFalse("format must be omitted, the core rejects null", json.containsKey("format"))
        assertEquals(JsonNull, json["login"])
        assertEquals(JsonNull, json["folder"])
        assertTrue(json.containsKey("ssh_key"))
        assertTrue(json["card"]!!.jsonObject.containsKey("cardholder_name"))
    }

    @Test
    fun toleratesMissingAndUnknownFields() {
        val item = ItemCodec.decode("""{"name":"Note","future_field":42,"login":{"username":"u","urls":[{"url":"a.com","match":"something_new"}]}}""")
        assertEquals("Note", item.name)
        assertEquals("", item.login!!.password)
        assertNull(item.login.totp)
        assertEquals(UrlMatch.Default, item.login.urls[0].match)
        assertEquals("a.com", item.siteHost)
    }

    @Test
    fun notesAreANoteKind() {
        assertEquals(ItemKind.Note, ItemCodec.decode("""{"name":"n","notes":"hi"}""").kind)
    }
}
