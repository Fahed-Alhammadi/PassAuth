package io.passauth.app.data

import io.passauth.app.autofill.SaveRule
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fields of newer apps inside an item's nested objects survive decode → edit → encode. */
class NestedFieldsTest {
    private val json = """
        {"name":"Site","notes":"","favorite":false,"folder":null,"tags":[],
         "login":{"username":"u","password":"old","future_login":1,
           "urls":[{"url":"https://a.example","match":"default","label":"Work"}],
           "totp":null,
           "passkeys":[{"credential_id":"Y3JlZA","rp_id":"a.example","rp_name":"A","user_handle":"dQ","user_name":"u","user_display_name":"U",
             "algorithm":-7,"private_key":"cGs","counter":0,"discoverable":true,"created_at":1,"backup_state":true}]},
         "card":{"cardholder_name":"","brand":"","number":"4111","exp_month":"","exp_year":"","code":"","issuer":{"name":"Bank"}},
         "identity":{"title":"","first_name":"A","middle_name":"","last_name":"","company":"","email":"","phone":"","address1":"","address2":"",
           "city":"","state":"","postal_code":"","country":"","username":"","ssn":"","passport_number":"","license_number":"","nickname":"Al"},
         "ssh_key":{"private_key":"k","public_key":"p","fingerprint":"f","comment":"laptop"},
         "fields":[{"name":"PIN","value":"1","type":"hidden","linked":"password"}],
         "password_history":[{"password":"older","changed_at":5,"device":"phone"}],
         "created_at":1,"updated_at":2,"attachments":"from-a-newer-app"}
    """.trimIndent()

    private fun checkKept(encoded: String) {
        val o = AppJson.parseToJsonElement(encoded).jsonObject
        val login = o["login"]!!.jsonObject
        assertEquals(JsonPrimitive(1), login["future_login"])
        assertEquals(JsonPrimitive("Work"), login["urls"]!!.jsonArray[0].jsonObject["label"])
        assertEquals(JsonPrimitive(true), login["passkeys"]!!.jsonArray[0].jsonObject["backup_state"])
        assertEquals("Bank", o["card"]!!.jsonObject["issuer"]!!.jsonObject["name"]!!.let { (it as JsonPrimitive).content })
        assertEquals(JsonPrimitive("Al"), o["identity"]!!.jsonObject["nickname"])
        assertEquals(JsonPrimitive("laptop"), o["ssh_key"]!!.jsonObject["comment"])
        assertEquals(JsonPrimitive("password"), o["fields"]!!.jsonArray[0].jsonObject["linked"])
        assertEquals(JsonPrimitive("phone"), o["password_history"]!!.jsonArray[0].jsonObject["device"])
        assertEquals(JsonPrimitive("from-a-newer-app"), o["attachments"])
    }

    @Test
    fun roundTripKeepsUnknownNestedFields() {
        val item = ItemCodec.decode(json)
        assertEquals(AppJson.parseToJsonElement(json), AppJson.parseToJsonElement(ItemCodec.encode(item)))
        checkKept(ItemCodec.encode(item))
    }

    @Test
    fun editsKeepThem() {
        val item = ItemCodec.decode(json)
        val edited = item.copy(
            name = "Renamed",
            login = item.login!!.copy(urls = item.login.urls.map { it.copy(url = it.url.trim()) }, totp = null),
            fields = item.fields.map { it.copy(value = "2") },
            identity = item.identity!!.copy(firstName = "B"),
        )
        // The editor's save: the file list as the item had it, even when it isn't a list.
        val saved = Attachments.withListOf(edited, item)
        checkKept(ItemCodec.encode(saved))
        assertEquals("Renamed", ItemCodec.decode(ItemCodec.encode(saved)).name)
    }

    @Test
    fun autofillPasswordUpdatesKeepThem() {
        val item = ItemCodec.decode(json)
        val updated = item.copy(login = SaveRule.apply(item.login!!, "new-user", "new-password"))
        val out = ItemCodec.encode(updated)
        checkKept(out)
        val back = ItemCodec.decode(out)
        assertEquals("new-password", back.login!!.password)
        assertEquals("new-user", back.login.username)
    }

    @Test
    fun aNonListFileValueIsntDroppedAndAListFollowsTheSyncedItem() {
        val draft = ItemCodec.decode("""{"name":"x"}""")
        val withText = Attachments.withListOf(draft, ItemCodec.decode("""{"name":"x","attachments":{"v":2}}"""))
        assertEquals(AppJson.parseToJsonElement("""{"v":2}"""), withText.extra["attachments"])
        val none = Attachments.withListOf(withText, ItemCodec.decode("""{"name":"x"}"""))
        assertTrue("attachments" !in none.extra)
    }
}
