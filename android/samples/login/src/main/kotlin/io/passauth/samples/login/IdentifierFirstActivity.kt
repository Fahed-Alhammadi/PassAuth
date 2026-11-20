package io.passauth.samples.login

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Identifier-first sign-in: the user name on this screen, the password on the next one (another
 * activity of the same task, as many apps do). The autofill service should offer to save both
 * together after the second screen.
 */
class IdentifierFirstActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val user = EditText(this).apply {
            id = R.id.username
            hint = "Email or username"
            setAutofillHints("username")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 160, 48, 48)
            addView(TextView(this@IdentifierFirstActivity).apply { text = "Sign in to Sample (step 1 of 2)"; textSize = 22f })
            addView(user)
            addView(Button(this@IdentifierFirstActivity).apply {
                id = R.id.next
                text = "Next"
                setOnClickListener {
                    startActivity(Intent(this@IdentifierFirstActivity, PasswordStepActivity::class.java).putExtra("user", user.text.toString()))
                    finish()
                }
            })
        }
        setContentView(col)
    }
}

/** Step 2: only the password (the user name is shown as text, as most sites do). */
class PasswordStepActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val name = intent.getStringExtra("user").orEmpty()
        val password = EditText(this).apply {
            id = R.id.password
            hint = "Password"
            setAutofillHints("password")
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 160, 48, 48)
            addView(TextView(this@PasswordStepActivity).apply { text = "Sign in to Sample (step 2 of 2)"; textSize = 22f })
            addView(TextView(this@PasswordStepActivity).apply { text = name; importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO })
            addView(password)
            addView(Button(this@PasswordStepActivity).apply {
                id = R.id.sign_in
                text = "Sign in"
                setOnClickListener {
                    startActivity(Intent(this@PasswordStepActivity, WelcomeActivity::class.java).putExtra("user", name))
                    finish()
                }
            })
        }
        setContentView(col)
    }
}
