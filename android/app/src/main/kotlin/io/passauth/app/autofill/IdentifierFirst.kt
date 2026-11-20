package io.passauth.app.autofill

/**
 * Identifier-first sign-in and sign-up: the user name on one screen, the password on the next.
 *
 * The user-name screen's response carries a [android.service.autofill.SaveInfo] with
 * `FLAG_DELAY_SAVE` (Android shows no save dialog for it but keeps the screen) and a client state
 * naming the place ([STATE_KEY] = [AutofillMatcher.neverSaveKey]). The password screen's request
 * gets that state back: its save then also says "user name", and `onSaveRequest` receives every
 * screen's `FillContext`, so one save offers the user name and the password together. The user
 * name is taken from an earlier screen only when the state names the same place as the password
 * screen and that screen is of the same place too (never from another site or app), and only when
 * the password screen has no user name of its own. What is saved then follows the save rule
 * ([SaveRule]) like any other save. Pure (JVM-tested in IdentifierFirstTest).
 */
object IdentifierFirst {
    /** Client-state key: the place whose user-name screen came before. */
    const val STATE_KEY = "io.passauth.identifierFirst"

    /** One screen of the flow, as far as this needs to know. */
    data class Step(val place: String?, val username: String?, val hasPassword: Boolean)

    /** A user-name screen: a user-name field and no password or one-time-code field. */
    fun isUsernameStep(form: LoginForm<*>): Boolean = form.username != null && form.passwords.isEmpty() && form.otp == null

    /** The password screen continues a user-name screen of [place] ([carried]: the state Android gave back). */
    fun continues(carried: String?, place: String): Boolean = carried != null && carried == place

    /**
     * The user name to save with the password typed on the last screen: [current] when that screen
     * has one, else the newest earlier user-name screen of [place] (when [carried] names it too).
     */
    fun username(current: String, earlier: List<Step>, place: String, carried: String?): String {
        if (current.isNotBlank() || !continues(carried, place)) return current
        return earlier.lastOrNull { it.place == place && !it.hasPassword && !it.username.isNullOrBlank() }?.username?.trim() ?: current
    }
}
