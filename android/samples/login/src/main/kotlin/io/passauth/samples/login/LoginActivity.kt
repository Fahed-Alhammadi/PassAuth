package io.passauth.samples.login

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.EditText
import android.widget.TextView

/** A plain username/password form (no autofill hints beyond the XML) to test the autofill service. */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.login)
        findViewById<android.view.View>(R.id.sign_in).setOnClickListener {
            val user = findViewById<EditText>(R.id.username).text.toString()
            startActivity(Intent(this, WelcomeActivity::class.java).putExtra("user", user))
            // Finishing the form ends the autofill session, which shows the save prompt.
            finish()
        }
        findViewById<android.view.View>(R.id.passkeys).setOnClickListener {
            startActivity(Intent(this, PasskeyActivity::class.java))
        }
    }
}

class WelcomeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "Signed in as ${intent.getStringExtra("user")}"
            textSize = 22f
            setTextColor(android.graphics.Color.BLACK)
            setPadding(48, 160, 48, 48)
        })
    }
}
