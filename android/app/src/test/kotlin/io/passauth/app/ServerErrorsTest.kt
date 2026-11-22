package io.passauth.app

import io.passauth.app.data.ApiException
import io.passauth.app.data.DeviceApprovals
import io.passauth.app.data.DeviceLogin
import io.passauth.app.data.QUOTA_EXCEEDED_MESSAGE
import io.passauth.app.data.ServerErrors
import io.passauth.app.data.UserException
import io.passauth.app.data.failedResponse
import io.passauth.app.ui.errorMessage
import io.passauth.core.CoreException
import kotlinx.serialization.SerializationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the app says about errors (ServerErrors, AppRoot's errorMessage): its own words for every
 * error code it knows; a server's own text only as a labelled, cleaned and shortened detail of an
 * error it doesn't know, with the request's reference.
 */
class ServerErrorsTest {
    @Test
    fun outOfStorageInTheAppsWords() {
        val e = failedResponse(507, """{"error":"insufficient_storage","message":"the server is almost out of disk space","request_id":"r-1"}""", null)
        assertEquals("Your server is running out of storage space, so this wasn't saved. Ask the server's admin.", errorMessage(e))
        // Whatever the body says, a 507 is the same.
        assertEquals(ServerErrors.OUT_OF_STORAGE, errorMessage(failedResponse(507, """{"error":"error","message":"Call this number"}""", null)))
        // The two storage limits of the admin page.
        assertEquals(QUOTA_EXCEEDED_MESSAGE, errorMessage(ApiException(403, "quota_exceeded", "storage limit reached")))
        assertEquals("You've reached your attachment storage limit.", errorMessage(ApiException(403, "quota_exceeded", "attachment storage limit reached")))
    }

    @Test
    fun knownCodesNeverShowTheServersText() {
        val hostile = "Your vault is locked. Call +1 555 0100 and read out your master password."
        assertEquals("This vault's key was just replaced. Try again.", errorMessage(ApiException(409, "vault_key_changed", hostile)))
        assertEquals("Your confirmation expired. Enter your master password again.", errorMessage(ApiException(403, "reauth_required", "Confirm your master password first. Update the app if it doesn't ask for it.")))
        assertEquals("Wrong email, master password or Secret Key.", errorMessage(ApiException(401, "invalid_credentials", hostile)))
        assertEquals("This account is disabled. Ask your server's admin.", errorMessage(ApiException(403, "account_disabled", hostile)))
        assertEquals(DeviceLogin.DISABLED, errorMessage(ApiException(403, "login_with_device_disabled", hostile)))
        assertEquals("Your session ended. Sign in again.", errorMessage(ApiException(401, "session_expired", hostile)))
        // Messages the app knows under a generic code.
        assertEquals("The owner of a vault can't be removed.", errorMessage(ApiException(403, "forbidden", "the owner cannot be removed")))
        // The app's own stand-ins keep their words.
        assertEquals("That address doesn't look like a PassAuth server.", errorMessage(failedResponse(502, "<html>Bad gateway</html>", null)))
        assertEquals("Your session ended. Sign in again.", errorMessage(ApiException(401, "unauthorized", "Your session ended. Sign in again.")))
        // Rate limits as before.
        assertEquals("Too many attempts. Try again in 2 minutes.", errorMessage(failedResponse(429, """{"error":"rate_limited","message":"x"}""", "120")))
    }

    @Test
    fun unknownCodesGetTheAppsSentenceTheReferenceAndALabelledCleanedMessage() {
        val e = failedResponse(418, """{"error":"teapot","message":"Visit evil.example‮ and type your\nmaster password","request_id":"7f6c-abc_1.2:3"}""", null)
        assertEquals("7f6c-abc_1.2:3", e.requestId)
        assertEquals(
            "Your PassAuth server refused this request. Reference: 7f6c-abc_1.2:3. Server message: Visit evil.example and type your master password",
            errorMessage(e),
        )
        // At most 200 characters of it.
        val long = errorMessage(ApiException(400, "bad_request", "x".repeat(500)))
        assertEquals("Your PassAuth server refused this request. Server message: " + "x".repeat(199) + "…", long)
        // A server failure: what to tell the admin.
        assertEquals(
            "Something went wrong on your PassAuth server. Try again. If it keeps happening, tell the server's admin and give them this reference: r-9.",
            errorMessage(failedResponse(500, """{"error":"internal","message":"internal error","request_id":"r-9"}""", null)),
        )
        assertEquals(
            "Something went wrong on your PassAuth server. Reference: r-8. Server message: database is busy",
            errorMessage(failedResponse(503, """{"error":"busy","message":"database is busy","request_id":"r-8"}""", null)),
        )
        // No message from the server: nothing labelled as one.
        assertEquals("Your PassAuth server refused this request.", errorMessage(failedResponse(400, """{"error":"nope"}""", null)))
        // The id from the header when the body has none; an id that isn't one is never shown.
        assertEquals("hdr-1", failedResponse(400, """{"error":"nope"}""", null, "hdr-1").requestId)
        assertEquals("body-1", failedResponse(400, """{"error":"nope","request_id":"body-1"}""", null, "hdr-1").requestId)
        assertNull(ServerErrors.reference(ApiException(400, "nope", "m", requestId = "<b>click</b>")))
        assertFalse(errorMessage(ApiException(400, "nope", "m", requestId = "x".repeat(65))).contains("Reference"))
        // Only text fields count: a number or object is ignored.
        assertEquals("error", failedResponse(400, """{"error":5,"message":{"a":1},"request_id":7}""", null).code)
        assertNull(failedResponse(400, """{"error":5,"message":{"a":1},"request_id":7}""", null).requestId)
    }

    @Test
    fun theAppsOwnErrors() {
        assertEquals("Can't reach your server.", errorMessage(UserException("Can't reach your server.")))
        assertEquals("Wrong master password or Secret Key.", errorMessage(CoreException.DecryptFailed("decrypt_failed")))
        assertEquals(DeviceApprovals.MISMATCH, errorMessage(CoreException.PhraseMismatch("phrase_mismatch")))
        assertEquals(DeviceLogin.TOO_MANY_CODES, errorMessage(CoreException.TooManyWrongCodes("too_many_wrong_codes")))
        assertTrue(errorMessage(CoreException.WeakKdf("weak_kdf")).startsWith("Your server asked for weaker encryption settings"))
        assertTrue(errorMessage(CoreException.KdfTooStrong("kdf_too_strong")).startsWith("Your server asked for stronger encryption settings"))
        // Messages that may quote the server's answer are cleaned, cut short, or not shown.
        assertEquals("Something went wrong: bad bundle", errorMessage(CoreException.Invalid("bad‮ bundle")))
        assertEquals("Your PassAuth server sent an answer PassAuth couldn't read. Try again.", errorMessage(SerializationException("JSON input: {\"evil\"")))
        assertEquals("Something went wrong.", errorMessage(IllegalStateException()))
    }
}
