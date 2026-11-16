package io.passauth.app.autofill

import io.passauth.app.autofill.SaveRule.Plan
import io.passauth.app.autofill.SaveRule.Reason
import io.passauth.app.autofill.SaveRule.asks
import io.passauth.app.autofill.SaveRule.updates
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

    // The rule's branches are the core's (crates/core/src/site/save_plan.rs) and are pinned by the
    // golden vectors (GoldenVectorsTest.savePlan, through this wrapper). Here: the wrapper itself.

    @Test
    fun theCoresPlanInTheAppsTerms() {
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(c("b", "sam", "x"), c("a", "alex", "old")), " ALEX ", "new"))
        assertEquals(Plan.Update("a", Reason.Blank), plan(listOf(c("a", "", "old")), "alex", "new"))
        assertEquals(Plan.Update("a", Reason.Only), plan(listOf(c("a", "alex", "old")), "", "new"))
        assertEquals(Plan.New, plan(listOf(c("a", "sam", "pw")), "alex", "pw"))
        assertEquals(Plan.Nothing, plan(listOf(c("a", "alex", "pw")), "alex", "pw"))
        assertEquals(Plan.Nothing, plan(emptyList(), "alex", ""))
        // Any id type: the core only sees the candidates' positions.
        val ints = listOf(SaveRule.Candidate(7, "Seven", "", "x", writable = true), SaveRule.Candidate(3, "Three", "alex", "y", writable = true))
        assertEquals(Plan.Update(3, Reason.Same), SaveRule.plan(ints, "alex", "new"))
        assertEquals(listOf(7, 3), SaveRule.targets(ints, "alex", "new").map { it.id })
        assertEquals(Plan.Update(7, Reason.Blank), SaveRule.planFor(ints, 7, "alex", "new"))
        // Nothing to save: nothing offered either.
        assertEquals(emptyList<Int>(), SaveRule.targets(ints, "alex", "y").map { it.id })
    }

    @Test
    fun aChoiceAfterThePasswordWasSavedMeanwhileChangesNothing() {
        // The sheet offered "a"; by the time the user confirms, the password is saved (another device).
        val now = listOf(c("a", "alex", "old"), c("b", "alex", "new"))
        assertEquals(Plan.Nothing, SaveRule.planFor(now, "a", "alex", "new"))
        // "New login" stays what the user chose.
        assertEquals(Plan.New, SaveRule.planFor(now, null, "alex", "new"))
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
    fun aSharedVaultLoginWithTheTypedUserNameIsOnlyOffered() {
        // Anyone can share a vault with the user and plant a login with the user's own email as
        // its user name: it is never selected, so a tap on "Update" can't send the password there.
        val planted = shared("s", "alex", "old")
        assertEquals(Plan.New, plan(listOf(planted), "ALEX", "new"))
        assertEquals(Plan.New, plan(listOf(planted, c("b", "", "x")), "alex", "new"))
        // The user's own login with the user name is the selection, wherever the shared one comes.
        assertEquals(Plan.Update("a", Reason.Same), plan(listOf(planted, c("a", "alex", "older")), "alex", "new"))
        // It is listed after the user's own logins, labelled with its vault...
        val targets = SaveRule.targets(listOf(planted, c("a", "alex", "older"), c("b", "sam", "x")), "alex", "new")
        assertEquals(listOf("a", "b", "s"), targets.map { it.id })
        assertEquals("Team", targets.last().vault)
        // ...and applied only when the user picks it, with a warning naming the vault.
        assertEquals(Plan.Update("s", Reason.Same), SaveRule.planFor(listOf(planted), "s", "alex", "new"))
        assertEquals("Saving here shares this password with everyone in Team.", SaveRule.sharedWarning(planted))
        assertNull(SaveRule.sharedWarning(c("a", "alex", "x")))
        assertNull(SaveRule.sharedWarning(null))
        // Already saved there: nothing to offer.
        assertEquals(Plan.Nothing, plan(listOf(planted.copy(password = "new")), "alex", "new"))
        // A view-only one with the user name is never offered.
        assertEquals(emptyList<String>(), SaveRule.targets(listOf(c("r", "alex", "old", writable = false)), "alex", "new").map { it.id })
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
        // ...except, after them, those with the typed user name (rule 1), shown with their vault's name.
        val withShared = SaveRule.targets(list, "kim", "new")
        assertEquals(listOf("a", "c", "s"), withShared.map { it.id })
        assertEquals("Team", withShared.last().vault)
        assertFalse(withShared.last().personal)
        // Never for an empty user name: a shared login without one is exactly what can be planted.
        assertEquals(listOf("a", "c"), SaveRule.targets(list, "", "new").map { it.id })

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
                // A password nobody saved is always saved somewhere (a view-only login doesn't block it).
                assertTrue(where, plan != Plan.Nothing)
                if (plan is Plan.Update && hint?.onlyTarget != null) assertEquals(where, "Item ${plan.id}", hint.onlyTarget)
                // No plan ever writes to a login outside the user's own vault: only the user's pick in "Save in" does.
                if (plan is Plan.Update) assertTrue(where, set.first { it.id == plan.id }.own)
            }
        }
    }
}
