package io.passauth.samples.login

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Calls Credential Manager like a native app would: create a passkey, sign in with
 * it (the signature is verified here with the public key from registration), or
 * get a saved password. The RP must list this app in its Digital Asset Links.
 */
class PasskeyActivity : Activity() {
    private val scope = MainScope()
    private lateinit var log: TextView
    private lateinit var rp: EditText
    private var publicKey: ByteArray? = null
    private var lastChallenge = ""

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun unb64(s: String) = Base64.decode(s, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun challenge() = ByteArray(32).also(SecureRandom()::nextBytes).let(::b64).also { lastChallenge = it }

    private fun say(s: String) {
        Log.i("PassAuthSample", s)
        log.append(s + "\n\n")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 120, 32, 32) }
        rp = EditText(this).apply { setText(intent.getStringExtra("rp") ?: "sample.passauth.test"); hint = "RP ID" }
        log = TextView(this).apply { setTextIsSelectable(true); textSize = 12f }
        col.addView(rp)
        col.addView(Button(this).apply { text = "Create passkey"; setOnClickListener { create() } })
        col.addView(Button(this).apply { text = "Sign in with passkey"; setOnClickListener { signIn() } })
        col.addView(Button(this).apply { text = "Get password"; setOnClickListener { password() } })
        col.addView(log)
        setContentView(ScrollView(this).apply { addView(col) })
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun create() = scope.launch {
        val rpId = rp.text.toString()
        val json = JSONObject()
            .put("rp", JSONObject().put("id", rpId).put("name", "Sample RP"))
            .put("user", JSONObject().put("id", b64("sample-user-1".toByteArray())).put("name", "sample@passauth.test").put("displayName", "Sample User"))
            .put("challenge", challenge())
            .put("pubKeyCredParams", org.json.JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
            .put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "required"))
            .toString()
        try {
            val r = CredentialManager.create(this@PasskeyActivity).createCredential(this@PasskeyActivity, CreatePublicKeyCredentialRequest(json))
            val resp = JSONObject((r as CreatePublicKeyCredentialResponse).registrationResponseJson)
            val response = resp.getJSONObject("response")
            publicKey = unb64(response.getString("publicKey"))
            val cdj = JSONObject(String(unb64(response.getString("clientDataJSON"))))
            say("CREATE OK id=${resp.getString("id")} alg=${response.getInt("publicKeyAlgorithm")} transports=${response.getJSONArray("transports")}")
            say("clientDataJSON type=${cdj.getString("type")} origin=${cdj.getString("origin")} challengeOk=${cdj.getString("challenge") == lastChallenge}")
        } catch (e: Exception) {
            say("CREATE FAILED ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun signIn() = scope.launch {
        val rpId = rp.text.toString()
        val json = JSONObject().put("rpId", rpId).put("challenge", challenge()).put("userVerification", "required").toString()
        try {
            val r = CredentialManager.create(this@PasskeyActivity).getCredential(this@PasskeyActivity, GetCredentialRequest(listOf(GetPublicKeyCredentialOption(json))))
            val c = r.credential as PublicKeyCredential
            val resp = JSONObject(c.authenticationResponseJson)
            val response = resp.getJSONObject("response")
            val authData = unb64(response.getString("authenticatorData"))
            val cdjBytes = unb64(response.getString("clientDataJSON"))
            val cdj = JSONObject(String(cdjBytes))
            val rpHashOk = authData.copyOfRange(0, 32).contentEquals(MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray()))
            var verified = "no public key from a create in this session"
            publicKey?.let { pk ->
                val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pk))
                val sig = Signature.getInstance("SHA256withECDSA")
                sig.initVerify(key)
                sig.update(authData + MessageDigest.getInstance("SHA-256").digest(cdjBytes))
                verified = sig.verify(unb64(response.getString("signature"))).toString()
            }
            say("GET OK id=${resp.getString("id")} userHandle=${String(unb64(response.optString("userHandle")))} flags=0x${"%02x".format(authData[32])}")
            say("clientDataJSON type=${cdj.getString("type")} origin=${cdj.getString("origin")} challengeOk=${cdj.getString("challenge") == lastChallenge} rpIdHashOk=$rpHashOk signatureValid=$verified")
        } catch (e: Exception) {
            say("GET FAILED ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun password() = scope.launch {
        try {
            val r = CredentialManager.create(this@PasskeyActivity).getCredential(this@PasskeyActivity, GetCredentialRequest(listOf(GetPasswordOption())))
            val c = r.credential as PasswordCredential
            say("PASSWORD OK user=${c.id} passwordLength=${c.password.length}")
        } catch (e: Exception) {
            say("PASSWORD FAILED ${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
