package io.passauth.app.data

/**
 * What the app says about an error answer from a server: its own wording for every error code it
 * knows (and for some message texts servers send under a generic code); for anything else a
 * sentence of its own with the request's reference, and the server's `message` only as a labelled
 * detail ("Server message: …"), cleaned and cut short ([ShownText]). A compromised server can't put
 * instructions of its own into the app's words this way. Mirrors the web vault's `apiErrorText`;
 * pure, unit-tested in ServerErrorsTest.
 */
object ServerErrors {
    /** 507 `insufficient_storage`: the server's disk is (nearly) full, so it refuses new data. */
    const val OUT_OF_STORAGE = "Your server is running out of storage space, so this wasn't saved. Ask the server's admin."

    /** 403 `quota_exceeded` for the admin's attachment storage limit. */
    const val ATTACHMENT_QUOTA = "You've reached your attachment storage limit."

    /** Longest piece of a server's own message that is shown, in characters. */
    const val MESSAGE_MAX = 200

    /** A request id worth showing: what servers make (letters, digits, `-_.:`, at most 64), never other text. */
    private val REQUEST_ID = Regex("[A-Za-z0-9_.:-]{1,64}")

    /** Server error codes with the app's own wording; the server's message is never shown for these. */
    private val CODES: Map<String, String> = mapOf(
        "reauth_required" to "Your confirmation expired. Enter your master password again.",
        "invalid_credentials" to "Wrong email, master password or Secret Key.",
        "email_not_verified" to "Confirm your email address first, then sign in.",
        "account_disabled" to "This account is disabled. Ask your server's admin.",
        "unauthorized" to "Your session ended. Sign in again.",
        "session_expired" to "Your session ended. Sign in again.",
        "vault_key_changed" to "This vault's key was just replaced. Try again.",
        "revision_conflict" to "This item was changed on another device.",
        "quota_exceeded" to QUOTA_EXCEEDED_MESSAGE,
        "insufficient_storage" to OUT_OF_STORAGE,
        "expired" to "This took too long and expired. Start again.",
        "invalid_code" to "That code didn't work. Enter the code that's showing now and try again.",
        "signups_closed" to "This server doesn't take new accounts at the moment. Ask the server's admin.",
        "account_exists" to "An account with this email address already exists. Sign in instead.",
        "not_found" to "Your PassAuth server couldn't find this. It may have been deleted on another device.",
        "item_exists" to "An item with the same id already exists. Try again.",
        "vault_exists" to "A vault with the same id already exists. Try again.",
        "last_vault" to "You can't delete your last vault.",
        "already_enabled" to "This is turned on already.",
        "too_large" to "This is larger than your server allows.",
        "two_step_required" to PolicyRules.TWO_STEP_REQUIRED_MESSAGE,
        "secret_key_required" to PolicyRules.SECRET_KEY_REQUIRED_MESSAGE,
        "kdf_too_weak" to PolicyRules.KDF_TOO_WEAK_MESSAGE,
        "login_with_device_disabled" to DeviceLogin.DISABLED,
        "sends_disabled" to "Send is turned off on this server.",
        "attachments_disabled" to "Adding files is turned off on this server.",
        "emergency_access_disabled" to "Emergency access is turned off on this server.",
        "attachment_exists" to "This file is being added already. Wait a moment, then try again.",
        "already_uploaded" to "This file was uploaded already.",
        "upload_in_progress" to "This file is being uploaded already. Wait a moment, then try again.",
        "wrong_password" to "That password is wrong. Check it and try again.",
        // Made by this app: an answer that isn't a PassAuth server's.
        "not_passauth" to "That address doesn't look like a PassAuth server.",
    )

    /**
     * Messages servers send under a generic code (`bad_request`, `forbidden`…) that the app knows,
     * with its own wording.
     */
    private val MESSAGES: Map<String, String> = mapOf(
        "email is not configured on this server" to "This server isn't set up to send email, so email codes aren't available.",
        "you can register at most 10 security keys" to "You can add at most 10 security keys. Remove one first.",
        "the owner cannot be removed" to "The owner of a vault can't be removed.",
        "invalid email address" to "Enter a valid email address.",
        "name too long" to "That name is too long. Shorten it and try again.",
    )

    /** The server's id for the request, when it looks like one. */
    fun reference(e: ApiException): String? = e.requestId?.takeIf { REQUEST_ID.matches(it) }

    /** The app's words for [e]. */
    fun text(e: ApiException): String {
        if (e.isRateLimited) return tooManyAttemptsMessage(e) ?: "Too many attempts. Wait a moment and try again."
        // Coded reasons first; a code shared by several limits is told apart by its message.
        if (e.code == "quota_exceeded" && e.message == "attachment storage limit reached") return ATTACHMENT_QUOTA
        if (e.status == 507) return OUT_OF_STORAGE
        (CODES[e.code] ?: MESSAGES[e.message.orEmpty()])?.let { return it }
        val reference = reference(e)
        // A failure inside the server: its log has the details under the request's id.
        if (e.status >= 500 && (e.code == "internal" || e.code == "error")) {
            return "Something went wrong on your PassAuth server. Try again. If it keeps happening, tell the server's admin" +
                (reference?.let { " and give them this reference: $it." } ?: ".")
        }
        val lead = if (e.status >= 500) "Something went wrong on your PassAuth server." else "Your PassAuth server refused this request."
        // "Request failed (…)" is this app's stand-in for a missing message: nothing from the server.
        val detail = ShownText.clean(e.message?.takeIf { it != "Request failed (${e.status})" }, MESSAGE_MAX)
        return listOfNotNull(lead, reference?.let { "Reference: $it." }, detail.ifEmpty { null }?.let { "Server message: $it" }).joinToString(" ")
    }
}
