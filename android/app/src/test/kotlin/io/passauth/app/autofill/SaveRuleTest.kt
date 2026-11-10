package io.passauth.app.autofill

import io.passauth.app.autofill.SaveRule.Plan
import io.passauth.app.autofill.SaveRule.Reason
import io.passauth.app.autofill.SaveRule.asks
import io.passauth.app.autofill.SaveRule.updates
import io.passauth.app.autofill.SaveRule.viewOnly
import io.passauth.app.data.Login
import io.passauth.app.data.LoginUrl
import io.passauth.app.data.UrlMatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The save rule (the same in every PassAuth client): every branch of the default plan. */
class SaveRuleTest {
    /** A login in the user's own vault, unless [writable] is false (view-only: a vault somebody shared). */
    private fun c(id: String, user: String, pw: String, writable: Boolean = true) =
        SaveRule.Candidate(id, "Item $id", user, pw, writable, personal = writable, vault = if (writable) "Personal" else "Family")

    /** A login in a vault somebody shared with write access: what an attacker can plant. */
    private fun shared(id: String, user: String, pw: String) = SaveRule.Candidate(id, "Item $id", user, pw, writable = true, personal = false, vault = "Team")

    private fun plan(list: List<SaveRule.Candidate<String>>, user: String, pw: String) = SaveRule.plan(list, user, pw)

    // ---- 1. a login with the typed user name

    @Test
    fun sameUserNameWithThePasswordIsUnchanged() {
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "pw")), "alex", "pw"))
        // Any of them: a second login with the same user name already has it.
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "old"), c("b", "alex", "pw")), "alex", "pw"))
    }

    @Test
    fun sameUserNameGetsTheNewPassword() {
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(c("a", "alex", "old")), "alex", "new"))
        // Compared trimmed and without case.
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(c("a", "Alex@Example.com", "old")), "  alex@example.COM ", "new"))
        // The first one the user can edit.
        assertEquals(Plan.Update("b", Reason.Same), plan(listOf(c("a", "alex", "old", writable = false), c("b", "alex", "older")), "alex", "new"))
    }

    @Test
    fun onlyTheUserNameWasSaved() {
        // An empty password is just a different password: the login is completed, not duplicated.
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(c("a", "alex", "")), "alex", "new"))
    }

    @Test
    fun sameUserNameInAViewOnlyVaultIsLeftAlone() {
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "old", writable = false)), "alex", "new"))
        // Even when another login could be edited: it belongs to someone else.
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "old", writable = false), c("b", "sam", "x")), "alex", "new"))
    }

    @Test
    fun noUserNameTypedAndALoginWithOnlyAPassword() {
        // `same` for an empty user name = the logins saved with only a password.
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(c("a", "", "old"), c("b", "alex", "x")), "", "new"))
        assertEquals(Plan.Nothing, plan(listOf(c("a", "", "pw")), "", "pw"))
        // A view-only login without a user name is not "the same login": the typed password is a new login.
        assertEquals(Plan.New, plan(listOf(c("a", "", "old", writable = false)), "", "new"))
        // ...unless it already has that password.
        assertEquals(Plan.Nothing, plan(listOf(c("a", "", "pw", writable = false)), "", "pw"))
    }

    // ---- 2. a new user name

    @Test
    fun onlyThePasswordWasSaved() {
        // The user's complaint: the login gets the user name (and password), no second item.
        assertEquals(Plan.Update("a", Reason.Blank), plan(listOf(c("a", "", "old")), "alex", "new"))
        // An update even when the password is unchanged: the user name gets filled in.
        assertEquals(Plan.Update("a", Reason.Blank), plan(listOf(c("a", "", "pw")), "alex", "pw"))
    }

    @Test
    fun severalLoginsWithoutAUserName() {
        // The one whose password was typed, else the first.
        assertEquals(Plan.Update("b", Reason.Blank), plan(listOf(c("a", "", "one"), c("b", "", "two")), "alex", "two"))
        assertEquals(Plan.Update("a", Reason.Blank), plan(listOf(c("a", "", "one"), c("b", "", "two")), "alex", "three"))
        // View-only ones are never picked.
        assertEquals(Plan.Update("b", Reason.Blank), plan(listOf(c("a", "", "pw", writable = false), c("b", "", "two")), "alex", "pw"))
    }

    @Test
    fun aNewUserNameIsANewLogin() {
        assertEquals(Plan.New, plan(emptyList(), "alex", "pw"))
        assertEquals(Plan.New, plan(listOf(c("a", "sam", "x")), "alex", "pw"))
        // The same password under another user name is still another account.
        assertEquals(Plan.New, plan(listOf(c("a", "sam", "pw")), "alex", "pw"))
        // A login without a user name that can't be edited doesn't count.
        assertEquals(Plan.New, plan(listOf(c("a", "", "x", writable = false)), "alex", "pw"))
    }

    // ---- 3. no user name typed, none saved without one

    @Test
    fun noUserNameTypedAndThePasswordIsAlreadySaved() {
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "pw"), c("b", "sam", "x")), "", "pw"))
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "pw", writable = false)), "", "pw"))
    }

    @Test
    fun noUserNameTypedAndExactlyOneLogin() {
        // The password belongs to the site's only login; its user name is kept.
        assertEquals(Plan.Update("a", Reason.Only), plan(listOf(c("a", "alex", "old")), "", "new"))
        assertEquals(Plan.Update("b", Reason.Only), plan(listOf(c("a", "sam", "x", writable = false), c("b", "alex", "old")), "", "new"))
    }

    @Test
    fun noUserNameTypedAndNoOrSeveralLogins() {
        assertEquals(Plan.New, plan(emptyList(), "", "pw"))
        assertEquals(Plan.New, plan(listOf(c("a", "alex", "old"), c("b", "sam", "x")), "", "new"))
        assertEquals(Plan.New, plan(listOf(c("a", "alex", "old", writable = false)), "", "new"))
    }

    @Test
    fun noPasswordIsNeverSaved() {
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "old")), "alex", ""))
        assertEquals(Plan.Nothing, plan(emptyList(), "alex", ""))
    }

    // ---- applying

    @Test
    fun applyingKeepsEverythingElse() {
        val login = Login(username = "", password = "old", urls = listOf(LoginUrl("https://example.com", UrlMatch.Host)), totp = "JBSWY3DPEHPK3PXP")
        val both = SaveRule.apply(login, " alex ", "new")
        assertEquals("alex", both.username)
        assertEquals("new", both.password)
        assertEquals(login.urls, both.urls)
        assertEquals(login.totp, both.totp)
        // No user name typed: the saved one stays.
        val kept = SaveRule.apply(login.copy(username = "sam"), "  ", "new")
        assertEquals("sam", kept.username)
        assertEquals("new", kept.password)
    }

    // ---- shared vaults: a login somebody else can plant never becomes the default place

    @Test
    fun aPlantedBlankLoginInASharedVaultIsNeverCompleted() {
        // Rule 2: the typed user name and password would go to the vault's other members.
        assertEquals(Plan.New, plan(listOf(shared("s", "", "x")), "alex", "new"))
        // The user's own blank login is chosen even when the planted one comes first or has the password.
        assertEquals(Plan.Update("a", Reason.Blank), plan(listOf(shared("s", "", "new"), c("a", "", "old")), "alex", "new"))
    }

    @Test
    fun aSharedVaultLoginIsNeverTheOnlyLogin() {
        // Rule 3: no user name typed, the one login for the place is in a shared vault.
        assertEquals(Plan.New, plan(listOf(shared("s", "alex", "x")), "", "new"))
        // It doesn't count towards "exactly one" either.
        assertEquals(Plan.Update("a", Reason.Only), plan(listOf(shared("s", "sam", "x"), c("a", "alex", "old")), "", "new"))
    }

    @Test
    fun noUserNameTypedNeverUpdatesABlankLoginInASharedVault() {
        // Rule 1 with an empty user name: "the same user name" proves nothing when both are empty.
        assertEquals(Plan.New, plan(listOf(shared("s", "", "x")), "", "new"))
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(shared("s", "", "x"), c("a", "", "old")), "", "new"))
        // Rule 3 then still applies to the user's own single login.
        assertEquals(Plan.Update("a", Reason.Only), plan(listOf(shared("s", "", "x"), c("a", "alex", "old")), "", "new"))
        // It still counts for "already saved": nothing to offer.
        assertEquals(Plan.Nothing, plan(listOf(shared("s", "", "new")), "", "new"))
    }

    @Test
    fun aSharedVaultLoginWithTheTypedUserNameIsStillUpdated() {
        // Rule 1 with a user name is unchanged: it needs the exact user name.
        assertEquals(Plan.Update("s", Reason.Same), plan(listOf(shared("s", "alex", "old")), "ALEX", "new"))
        assertEquals(Plan.Nothing, plan(listOf(shared("s", "alex", "new")), "alex", "new"))
    }

    // ---- saving without PassAuth's own sheet

    @Test
    fun theOnlyLoginIsNeverOverwrittenWithoutTheSheet() {
        val only = plan(listOf(c("a", "alex", "old")), "", "new")
        assertTrue(SaveRule.needsSheet(only))
        assertEquals(Plan.New, SaveRule.withoutSheet(only))
        // Rules 1 and 2, new logins and "nothing" are applied as they are.
        for (p in listOf(Plan.Update("a", Reason.Same), Plan.Update("a", Reason.Blank), Plan.Update("a", Reason.Picked), Plan.New, Plan.Nothing)) {
            assertFalse(SaveRule.needsSheet(p))
            assertEquals(p, SaveRule.withoutSheet(p))
        }
    }

    // ---- "Save in" (the sheet PassAuth shows before it saves)

    @Test
    fun saveInChoices() {
        val list = listOf(c("a", "alex", "pw"), c("b", "sam", "x", writable = false), c("c", "", "y"), shared("s", "kim", "z"), shared("t", "", "z"))
        // The user's own logins; shared-vault ones are not offered...
        assertEquals(listOf("a", "c"), SaveRule.targets(list, "robin", "new").map { it.id })
        // ...except the one rule 1 preselects (the typed user name), shown with its vault's name.
        val withShared = SaveRule.targets(list, "kim", "new")
        assertEquals(listOf("a", "c", "s"), withShared.map { it.id })
        assertEquals("Team", withShared.last().vault)
        assertFalse(withShared.last().personal)
        // No shared login is offered once it already has the typed password (nothing to update).
        assertEquals(listOf("a", "c"), SaveRule.targets(list, "kim", "z").map { it.id })

        assertEquals(Plan.New, SaveRule.planFor(list, null, "alex", "new"))
        assertEquals(Plan.Update("c", Reason.Blank), SaveRule.planFor(list, "c", "alex", "new"))
        assertEquals(Plan.Update("a", Reason.Same), SaveRule.planFor(list, "a", "Alex", "new"))
        assertEquals(Plan.Update("a", Reason.Picked), SaveRule.planFor(list, "a", "other", "pw"))
        assertEquals(Plan.Update("s", Reason.Same), SaveRule.planFor(list, "s", "kim", "new"))
        // Already there: same user name (or none typed) and password.
        assertEquals(Plan.Nothing, SaveRule.planFor(list, "a", "ALEX", "pw"))
        assertEquals(Plan.Nothing, SaveRule.planFor(list, "a", "", "pw"))
        // Never a login this save didn't offer: view-only, a shared vault's, or not for this site at all.
        assertNull(SaveRule.planFor(list, "b", "sam", "new"))
        assertNull(SaveRule.planFor(list, "s", "robin", "new"))
        assertNull(SaveRule.planFor(list, "t", "robin", "new"))
        assertNull(SaveRule.planFor(list, "t", "", "new"))
        assertNull(SaveRule.planFor(list, "zzz", "alex", "new"))
        assertEquals(Plan.Nothing, SaveRule.planFor(list, "a", "alex", ""))
    }

    @Test
    fun describesWhatSavingDoes() {
        assertEquals("Saves alex and the password for example.com as a new login.", SaveRule.describe(null, "alex", "example.com"))
        assertEquals("Saves the password for example.com as a new login, without a user name.", SaveRule.describe(null, "", "example.com"))
        assertEquals("Updates the password for alex.", SaveRule.describe(c("a", "alex", "x"), "ALEX", "example.com"))
        assertEquals("Updates the password for alex.", SaveRule.describe(c("a", "alex", "x"), "", "example.com"))
        assertEquals("Updates the password. The login has no user name.", SaveRule.describe(c("a", "", "x"), "", "example.com"))
        assertEquals("Adds the user name alex and updates the password.", SaveRule.describe(c("a", "", "x"), "alex", "example.com"))
        assertEquals("Changes the user name from sam to alex and updates the password.", SaveRule.describe(c("a", "sam", "x"), "alex", "example.com"))
    }

    // ---- the hint for Android's save dialog

    @Test
    fun hintIsNullWhenEverySaveIsANewLogin() {
        assertNull(SaveRule.hint(emptyList<SaveRule.Candidate<String>>()))
        // A planted blank login in a shared vault changes nothing: every save is a new login.
        assertNull(SaveRule.hint(listOf(shared("s", "", "x"))))
        // Several logins, none without a user name: a blank user name is a new login, and so is any other name...
        val h = SaveRule.hint(listOf(c("a", "alex", "x"), c("b", "sam", "y")))!!
        // ...but the saved names update.
        assertTrue(h.updates("Alex"))
        assertFalse(h.updates("robin"))
        assertFalse(h.updates(""))
        assertFalse(h.asks(""))
        assertNull(h.onlyTarget)
    }

    @Test
    fun hintNamesTheOnlyLogin() {
        val h = SaveRule.hint(listOf(c("a", "", "x")))!!
        assertEquals("Item a", h.onlyTarget)
        assertTrue(h.updates(""))
        assertTrue(h.updates("anyone at all"))
        // A shared login that can never be updated doesn't make the target ambiguous.
        assertEquals("Item a", SaveRule.hint(listOf(shared("s", "", "y"), c("a", "", "x")))!!.onlyTarget)
    }

    @Test
    fun hintSaysWhenPassAuthAsksFirst() {
        // No user name typed and one login of the user's own: the sheet follows, nothing is updated silently.
        val h = SaveRule.hint(listOf(c("a", "alex", "x")))!!
        assertTrue(h.asks(""))
        assertTrue(h.asks("   "))
        assertFalse(h.updates(""))
        assertTrue(h.updates("alex"))
        assertFalse(h.asks("alex"))
    }

    @Test
    fun hintTreatsUserNamesLiterally() {
        // A user name is never a pattern: "a.c" must not match "abc", and odd characters can't break out.
        val h = SaveRule.hint(listOf(c("a", "a.c", "x"), c("b", "x)|(.*", "y"), c("c", "q\\E.*", "z")))!!
        assertTrue(h.updates("A.C"))
        assertFalse(h.updates("abc"))
        assertTrue(h.updates("x)|(.*"))
        assertTrue(h.updates("q\\E.*"))
        assertFalse(h.updates("q\\Eanything"))
        assertFalse(h.updates("anything"))
    }

    /** The hint must say exactly what the plan does, for any typed user name (the password being a new one). */
    @Test
    fun hintAgreesWithThePlan() {
        val users = listOf("", "alex", "sam", "kim")
        // Every login is the user's own, in a shared vault with write access, or view-only.
        val kinds = listOf<(String, String, String) -> SaveRule.Candidate<String>>(
            { id, u, pw -> c(id, u, pw) },
            { id, u, pw -> shared(id, u, pw) },
            { id, u, pw -> c(id, u, pw, writable = false) },
        )
        val options = users.flatMap { u -> kinds.map { k -> u to k } }
        // Every vault of up to three logins over these user names and kinds.
        val sets = mutableListOf<List<SaveRule.Candidate<String>>>()
        for (a in options) {
            sets += listOf(a.second("1", a.first, "p1"))
            for (b in options) {
                sets += listOf(a.second("1", a.first, "p1"), b.second("2", b.first, "p2"))
                for (d in options) sets += listOf(a.second("1", a.first, "p1"), b.second("2", b.first, "p2"), d.second("3", d.first, "p3"))
            }
        }
        val typed = listOf("", "  ", "alex", " ALEX ", "sam", "kim", "robin", "al")
        for (set in sets) {
            val hint = SaveRule.hint(set)
            for (t in typed) {
                val plan = SaveRule.plan(set, t, "a password nobody saved")
                val where = "vault ${set.map { "${it.username}/${it.writable}/${it.personal}" }} typed '$t'"
                val silent = plan is Plan.Update && plan.reason != Reason.Only
                assertEquals(where, silent, hint?.updates(t) == true)
                assertEquals(where, SaveRule.needsSheet(plan), hint?.asks(t) == true)
                assertEquals(where, plan == Plan.Nothing, hint?.viewOnly(t) == true)
                if (plan is Plan.Update && hint?.onlyTarget != null) assertEquals(where, "Item ${plan.id}", hint.onlyTarget)
                // No plan ever updates a shared-vault login unless it has the typed user name.
                if (plan is Plan.Update) {
                    val target = set.first { it.id == plan.id }
                    assertTrue(where, target.own || (t.isNotBlank() && target.username == t.trim().lowercase()))
                }
            }
        }
    }
}
