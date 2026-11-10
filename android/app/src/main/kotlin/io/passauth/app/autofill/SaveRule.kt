package io.passauth.app.autofill

import io.passauth.app.data.Login

/**
 * The save rule, the same in every PassAuth client: what to do with a user name and
 * password the user just submitted where the vault already has (or doesn't have) logins.
 * A login already saved for the site or app is updated instead of saving a second one.
 * Pure (no Android, no vault): unit-tested in SaveRuleTest.
 *
 * Shared vaults: anyone on the server can share a vault with this account and put a login
 * for a site in it. Such a login is only ever updated when it has the exact user name that
 * was typed (rule 1 with a user name). The looser rules use logins in the account's own
 * vault only, so a planted login can't become the place a typed user name and password are
 * written to.
 */
object SaveRule {
    /** A vault login that matches the site or app, in the matcher's order. */
    data class Candidate<K>(
        val id: K,
        val name: String,
        val username: String,
        val password: String,
        /** In a vault the user can edit. */
        val writable: Boolean,
        /** In the user's own vault (not one somebody shared). */
        val personal: Boolean = true,
        /** The vault's name, shown on the row of a shared-vault login. */
        val vault: String = "",
    ) {
        /** One of the user's own logins: the only kind the looser rules may update. */
        val own: Boolean get() = writable && personal
    }

    /** Which rule made an update the default. */
    enum class Reason {
        /** Rule 1: the login has the typed user name. */
        Same,

        /** Rule 2: a login of the user's own that was saved with only a password. */
        Blank,

        /**
         * Rule 3: no user name was typed and it is the user's only login for the place. Never
         * applied without PassAuth's own sheet: the user sees which login changes.
         */
        Only,

        /** No rule: the user chose this login in "Save in". */
        Picked,
    }

    sealed interface Plan<out K> {
        /** Nothing to save: already saved with this password, a view-only login, or no password. */
        data object Nothing : Plan<kotlin.Nothing>

        /** A new login. */
        data object New : Plan<kotlin.Nothing>

        /** The login [id] gets the typed password (and the typed user name, if one was typed). */
        data class Update<K>(val id: K, val reason: Reason) : Plan<K>
    }

    private fun norm(s: String) = s.trim().lowercase()

    /**
     * The default plan for the typed user name (may be empty: the form showed no user-name
     * field) and password, given the logins that match the site or app.
     *
     * 0. No password → nothing.
     * 1. Logins saved under this very user name (for an empty one: logins saved with only a
     *    password): one already has the password → nothing; else one the user can edit →
     *    update it; else (view-only) → nothing. With no user name typed only the user's OWN
     *    logins are updated this way: "the same user name" proves nothing when both are empty,
     *    and a login without a user name is exactly what somebody could plant in a shared vault.
     * 2. None, and a user name was typed: one of the user's OWN logins that has no user name
     *    (only a password was saved) → update it, preferring the one with the typed password,
     *    else the first; none → a new login.
     * 3. None, and no user name was typed: the password is already saved here → nothing;
     *    exactly one login of the user's OWN → update it; otherwise → a new login.
     */
    fun <K> plan(candidates: List<Candidate<K>>, typedUser: String, password: String): Plan<K> {
        if (password.isEmpty()) return Plan.Nothing
        val user = norm(typedUser)
        val own = candidates.filter { it.own }

        val same = candidates.filter { norm(it.username) == user }
        if (same.any { it.password == password }) return Plan.Nothing
        val trusted = if (user.isEmpty()) same.filter { it.own } else same
        trusted.firstOrNull { it.writable }?.let { return Plan.Update(it.id, Reason.Same) }
        if (trusted.isNotEmpty()) return Plan.Nothing

        if (user.isNotEmpty()) {
            val bare = own.filter { norm(it.username).isEmpty() }
            val pick = bare.firstOrNull { it.password == password } ?: bare.firstOrNull()
            return pick?.let { Plan.Update(it.id, Reason.Blank) } ?: Plan.New
        }
        if (candidates.any { it.password == password }) return Plan.Nothing
        return if (own.size == 1) Plan.Update(own[0].id, Reason.Only) else Plan.New
    }

    /**
     * The plan where PassAuth can't show its own sheet (a save applied at the next unlock):
     * a rule-3 update becomes a new login, because nobody would see which login changes.
     * Rule-1 and rule-2 updates and new logins are applied as they are.
     */
    fun <K> withoutSheet(plan: Plan<K>): Plan<K> = if (needsSheet(plan)) Plan.New else plan

    /** Must the user see PassAuth's sheet before this plan is applied? (A rule-3 update.) */
    fun needsSheet(plan: Plan<*>): Boolean = plan is Plan.Update && plan.reason == Reason.Only

    /**
     * "Save in": the user's own logins for the place, plus the login rule 1 preselects when
     * that one is in a shared vault (so the sheet can show it as the selection, with its
     * vault's name). In the matcher's order; the sheet lists them above "New login".
     */
    fun <K> targets(candidates: List<Candidate<K>>, typedUser: String, password: String): List<Candidate<K>> {
        val p = plan(candidates, typedUser, password)
        val shared = (p as? Plan.Update)?.takeIf { it.reason == Reason.Same }?.id
        return candidates.filter { it.own || (shared != null && it.id == shared) }
    }

    /**
     * What saving does with the user's "Save in" choice ([target] = a login's id, or null for
     * a new login). A choice that isn't one of [targets] is refused (null); a chosen login
     * that already has the typed user name (or none was typed) and password is unchanged.
     */
    fun <K> planFor(candidates: List<Candidate<K>>, target: K?, typedUser: String, password: String): Plan<K>? {
        if (password.isEmpty()) return Plan.Nothing
        if (target == null) return Plan.New
        val c = targets(candidates, typedUser, password).firstOrNull { it.id == target } ?: return null
        val user = norm(typedUser)
        val saved = norm(c.username)
        val sameUser = saved == user
        if ((sameUser || user.isEmpty()) && c.password == password) return Plan.Nothing
        return Plan.Update(c.id, if (sameUser) Reason.Same else if (saved.isEmpty()) Reason.Blank else Reason.Picked)
    }

    /**
     * A login after the submitted credentials were saved into it: the password always, the
     * user name only when one was typed. Everything else is untouched (the repository's
     * update keeps the old password in the history).
     */
    fun apply(login: Login, typedUser: String, password: String): Login =
        login.copy(username = typedUser.trim().ifEmpty { login.username }, password = password)

    /** One sentence naming what saving into [target] (null = a new login) will do; [place] is the site or app. */
    fun describe(target: Candidate<*>?, typedUser: String, place: String): String {
        val user = typedUser.trim()
        if (target == null) {
            return if (user.isNotEmpty()) "Saves $user and the password for $place as a new login."
            else "Saves the password for $place as a new login, without a user name."
        }
        val saved = target.username.trim()
        return when {
            user.isEmpty() -> if (saved.isNotEmpty()) "Updates the password for $saved." else "Updates the password. The login has no user name."
            saved.isEmpty() -> "Adds the user name $user and updates the password."
            norm(saved) == norm(user) -> "Updates the password for $saved."
            else -> "Changes the user name from $saved to $user and updates the password."
        }
    }

    /**
     * What Android's own save dialog can be told before the user types anything: for which
     * typed user names the default plan updates a saved login without asking ([updateUser], a
     * regular expression over the whole user-name field; [updateWhenBlank] for an empty or
     * missing field), when PassAuth asks first with its own sheet ([askWhenBlank]: rule 3), and
     * for which names it leaves a view-only login alone ([viewOnlyUser]). Everything else is a
     * new login. The password is not part of it: saved passwords never go into the hint.
     */
    data class Hint(
        val updateUser: String?,
        val updateWhenBlank: Boolean,
        val askWhenBlank: Boolean,
        val viewOnlyUser: String?,
        /** The one login every update goes to, when there is only one that could be updated. */
        val onlyTarget: String?,
    )

    /** The [Hint] for the logins that match the site or app; null when every save is a new login. */
    fun <K> hint(candidates: List<Candidate<K>>): Hint? {
        if (candidates.isEmpty()) return null
        val own = candidates.filter { it.own }
        val byName = candidates.groupBy { norm(it.username) }
        // Rule 1 with a user name: a name that is already saved (in any vault the user can edit).
        val updateNames = byName.filter { (n, l) -> n.isNotEmpty() && l.any { it.writable } }.keys
        val viewOnlyNames = byName.filter { (n, l) -> n.isNotEmpty() && l.none { it.writable } }.keys
        // Rules 1 (no user name) and 2: only the user's own logins saved with only a password.
        val ownBare = byName[""].orEmpty().any { it.own }
        // Rule 3: no user name, none of the user's own saved without one, exactly one of their own.
        val askWhenBlank = !ownBare && own.size == 1

        fun alt(names: Set<String>) = names.joinToString("|") { Regex.escape(it) }
        val updateUser = when {
            // Rule 2: any other user name completes the login saved with only a password.
            ownBare && viewOnlyNames.isEmpty() -> "\\s*\\S[\\s\\S]*"
            ownBare -> "\\s*(?!(?:${alt(viewOnlyNames)})\\s*$)\\S[\\s\\S]*"
            updateNames.isNotEmpty() -> "\\s*(?:${alt(updateNames)})\\s*"
            else -> null
        }
        val viewOnlyUser = viewOnlyNames.takeIf { it.isNotEmpty() }?.let { "\\s*(?:${alt(it)})\\s*" }
        if (updateUser == null && !ownBare && !askWhenBlank && viewOnlyUser == null) return null
        // Every login an update could go to: one with a user name the user can edit (rule 1), or one of their own.
        val reachable = candidates.filter { it.own || (it.writable && norm(it.username).isNotEmpty()) }
        return Hint(updateUser, ownBare, askWhenBlank, viewOnlyUser, reachable.singleOrNull()?.name)
    }

    /** Is [typedUser] one the hint says updates a saved login without asking? (What Android's validators compute.) */
    fun Hint.updates(typedUser: String): Boolean =
        if (typedUser.isBlank()) updateWhenBlank else updateUser?.let { Regex(it, HINT_OPTIONS).matches(typedUser) } == true

    /** Is [typedUser] one for which PassAuth shows its sheet before updating? */
    fun Hint.asks(typedUser: String): Boolean = typedUser.isBlank() && askWhenBlank

    fun Hint.viewOnly(typedUser: String): Boolean =
        typedUser.isNotBlank() && viewOnlyUser?.let { Regex(it, HINT_OPTIONS).matches(typedUser) } == true

    /** User names compare without case, like the plan. */
    val HINT_OPTIONS = setOf(RegexOption.IGNORE_CASE)
}
