package io.passauth.app.autofill

import io.passauth.app.data.Login
import io.passauth.core.SaveCandidate
import io.passauth.core.SavePlan
import io.passauth.core.SaveReason
import io.passauth.core.SaveTarget
import io.passauth.core.chosenSaveTarget
import io.passauth.core.planSave

/**
 * The save rule, the same in every PassAuth client: what to do with a user name and
 * password the user just submitted where the vault already has (or doesn't have) logins.
 * A login already saved for the site or app is updated instead of saving a second one.
 * The rule itself is the Rust core's (`planSave` / `chosenSaveTarget`, crates/core/src/site,
 * checked by the golden vectors); this object puts it in the app's terms (candidates of any id
 * type, [Plan]) and keeps what is Android's own: the wording, [withoutSheet] and the [hint] for
 * Android's save dialog. Unit-tested in SaveRuleTest.
 *
 * Shared vaults: anyone on the server can share a vault with this account (no consent needed)
 * and put a login for a site in it, even one with the user's own email as its user name. So a
 * login in a shared vault is never chosen by a rule: rule 1 only lists one with the typed user
 * name as an extra, unselected choice in "Save in" (labelled with its vault, with a warning when
 * picked), and it is written to only when the user picks it there. The default place is always
 * the user's own vault: one of their logins, or a new login.
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

    /** The core's plan for [candidates] (ids "0", "1", … = their indices) and the logins it offers. */
    private class Decision<K>(val plan: Plan<K>, val offered: List<SaveTarget>, private val candidates: List<Candidate<K>>) {
        val targets: List<Candidate<K>> get() = offered.map { candidates[it.id.toInt()] }

        /** The candidate the prompt's answer [id] stands for, when the core accepts it as one it offered. */
        fun chosen(id: K): Candidate<K>? {
            val answer = offered.firstOrNull { candidates[it.id.toInt()].id == id }?.id ?: return null
            return chosenSaveTarget(offered, answer)?.let { candidates[it.toInt()] }
        }
    }

    private fun <K> decide(candidates: List<Candidate<K>>, typedUser: String, password: String): Decision<K> {
        // Indices as ids: any id type works, and the core never sees the app's ids.
        val core = candidates.mapIndexed { i, c ->
            SaveCandidate(i.toString(), c.name, c.username, c.password, c.writable, c.personal, c.vault.takeIf { !c.personal && it.isNotEmpty() })
        }
        return when (val p = planSave(core, typedUser, password)) {
            SavePlan.None -> Decision(Plan.Nothing, emptyList(), candidates)
            is SavePlan.Create -> Decision(Plan.New, p.targets, candidates)
            is SavePlan.Update -> Decision(Plan.Update(candidates[p.target.toInt()].id, reasonOf(p.reason)), p.targets, candidates)
        }
    }

    private fun reasonOf(r: SaveReason) = when (r) {
        SaveReason.SAME -> Reason.Same
        SaveReason.BLANK -> Reason.Blank
        SaveReason.ONLY -> Reason.Only
    }

    /**
     * The default plan for the typed user name (may be empty: the form showed no user-name
     * field) and password, given the logins that match the site or app (the core's `planSave`):
     *
     * 0. No password → nothing.
     * 1. Logins saved under this very user name (for an empty one: the user's OWN logins saved
     *    with only a password; "the same user name" proves nothing when both are empty): one
     *    already has the password (in any vault) → nothing; else the first of the user's OWN →
     *    update it; none of their own (only shared or view-only ones) → a new login. Shared ones
     *    the user can edit are only offered in "Save in" ([targets]).
     * 2. None, and a user name was typed: one of the user's OWN logins that has no user name
     *    (only a password was saved) → update it, preferring the one with the typed password,
     *    else the first; none → a new login.
     * 3. None, and no user name was typed: the password is already saved here → nothing;
     *    exactly one login of the user's OWN → update it; otherwise → a new login.
     */
    fun <K> plan(candidates: List<Candidate<K>>, typedUser: String, password: String): Plan<K> =
        decide(candidates, typedUser, password).plan

    /**
     * The plan where PassAuth can't show its own sheet (a save applied at the next unlock):
     * a rule-3 update becomes a new login, because nobody would see which login changes.
     * Rule-1 and rule-2 updates and new logins are applied as they are.
     */
    fun <K> withoutSheet(plan: Plan<K>): Plan<K> = if (needsSheet(plan)) Plan.New else plan

    /** Must the user see PassAuth's sheet before this plan is applied? (A rule-3 update.) */
    fun needsSheet(plan: Plan<*>): Boolean = plan is Plan.Update && plan.reason == Reason.Only

    /**
     * "Save in": the user's own logins for the place, then the logins in shared vaults the user
     * can edit that have the typed user name (rule 1's extra choices, never preselected; never
     * for an empty user name). In the matcher's order; the sheet lists them above "New login".
     * Empty when there is nothing to save.
     */
    fun <K> targets(candidates: List<Candidate<K>>, typedUser: String, password: String): List<Candidate<K>> =
        decide(candidates, typedUser, password).targets

    /** The sheet's warning for a choice in a shared vault (null for the user's own vault or a new login). */
    fun sharedWarning(target: Candidate<*>?): String? =
        target?.takeIf { !it.personal }?.let { "Saving here shares this password with everyone in ${it.vault.ifEmpty { "this shared vault" }}." }

    /**
     * What saving does with the user's "Save in" choice ([target] = a login's id, or null for
     * a new login), on the logins as they are now. Nothing when the password is saved by now (on
     * another device, or by an earlier try). A login the save doesn't offer (any more) is refused
     * (null): the core accepts only one of the plan's targets. A chosen login that already has the
     * typed user name (or none was typed) and password is unchanged.
     */
    fun <K> planFor(candidates: List<Candidate<K>>, target: K?, typedUser: String, password: String): Plan<K>? {
        if (password.isEmpty()) return Plan.Nothing
        if (target == null) return Plan.New
        val d = decide(candidates, typedUser, password)
        if (d.plan == Plan.Nothing) return Plan.Nothing
        val c = d.chosen(target) ?: return null
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
     * missing field) and when PassAuth asks first with its own sheet ([askWhenBlank]: rule 3).
     * Everything else is a new login. The password is not part of it: saved passwords never go
     * into the hint.
     */
    data class Hint(
        val updateUser: String?,
        val updateWhenBlank: Boolean,
        val askWhenBlank: Boolean,
        /** The one login every update goes to, when there is only one that could be updated. */
        val onlyTarget: String?,
    )

    /** The [Hint] for the logins that match the site or app; null when every save is a new login. */
    fun <K> hint(candidates: List<Candidate<K>>): Hint? {
        if (candidates.isEmpty()) return null
        val own = candidates.filter { it.own }
        // Rule 1 with a user name: a name one of the user's own logins has.
        val ownNames = own.map { norm(it.username) }.filter { it.isNotEmpty() }.toSet()
        // Names only shared or view-only logins have: rule 1 makes those a new login, not rule 2.
        val otherNames = candidates.map { norm(it.username) }.filter { it.isNotEmpty() }.toSet() - ownNames
        // Rules 1 (no user name) and 2: only the user's own logins saved with only a password.
        val ownBare = own.any { norm(it.username).isEmpty() }
        // Rule 3: no user name, none of the user's own saved without one, exactly one of their own.
        val askWhenBlank = !ownBare && own.size == 1

        fun alt(names: Set<String>) = names.joinToString("|") { Regex.escape(it) }
        val updateUser = when {
            // Rule 2: any user name nobody has saved completes the login saved with only a password.
            ownBare && otherNames.isEmpty() -> "\\s*\\S[\\s\\S]*"
            ownBare -> "\\s*(?!(?:${alt(otherNames)})\\s*$)\\S[\\s\\S]*"
            ownNames.isNotEmpty() -> "\\s*(?:${alt(ownNames)})\\s*"
            else -> null
        }
        if (updateUser == null && !ownBare && !askWhenBlank) return null
        // Every update goes to one of the user's own logins.
        return Hint(updateUser, ownBare, askWhenBlank, own.singleOrNull()?.name)
    }

    /** Is [typedUser] one the hint says updates a saved login without asking? (What Android's validators compute.) */
    fun Hint.updates(typedUser: String): Boolean =
        if (typedUser.isBlank()) updateWhenBlank else updateUser?.let { Regex(it, HINT_OPTIONS).matches(typedUser) } == true

    /** Is [typedUser] one for which PassAuth shows its sheet before updating? */
    fun Hint.asks(typedUser: String): Boolean = typedUser.isBlank() && askWhenBlank

    /** User names compare without case, like the plan. */
    val HINT_OPTIONS = setOf(RegexOption.IGNORE_CASE)
}
