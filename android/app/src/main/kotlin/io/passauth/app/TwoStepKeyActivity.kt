package io.passauth.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import io.passauth.app.data.SecurityKeyHandoff

/**
 * Receives `passauth://two-step-key#…` from the server's key page when the browser opened it in a
 * Custom Tab (browsers with Auth Tab return the result to the sign-in screen directly). It only
 * forwards the URL to the sign-in waiting for it ([SecurityKeyHandoff.waiter]) and brings PassAuth
 * back to the front, closing the tab above it; when nothing waits, or the URL isn't a callback for
 * the challenge being waited for, it does nothing. It has no UI and no task of its own.
 *
 * Any app can declare the same scheme. That can only deny service: the assertion alone can't finish
 * a sign-in, because the two-factor token never leaves PassAuth.
 */
class TwoStepKeyActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null && intent?.action == Intent.ACTION_VIEW && SecurityKeyHandoff.waiter.deliver(intent.dataString)) {
            startActivity(
                Intent(this, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        }
        finish()
    }
}
