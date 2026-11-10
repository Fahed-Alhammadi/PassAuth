// Tests for the save rule (src/background/save-plan.ts): update an existing login instead of saving a duplicate.
// Run with plain Node (type stripping):  node extension/test/save-plan.test.mjs

import assert from "node:assert/strict";
import { applyToLogin, chosenTarget, describeSave, NEW_LOGIN, planSave } from "../src/background/save-plan.ts";

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

let n = 0;
/** A login that matches the page. */
const c = (username, password, extra = {}) => ({ id: `id-${++n}`, name: `Login ${n}`, username, password, writable: true, personal: true, ...extra });
/** In the user's own vault, but read-only (cannot normally happen; the rule must still not write to it). */
const ro = (username, password) => c(username, password, { writable: false });
/** In a vault somebody shared with the user, with write access: what an attacker can plant. */
const shared = (username, password, extra = {}) => c(username, password, { personal: false, vault: "Family", ...extra });
/** Shared and read-only. */
const sharedRo = (username, password) => shared(username, password, { writable: false });
const NONE = { action: "none" };

// ------------------------------------------------------------------ 1. same user name

test("same user name, same password: nothing to offer", () => {
  assert.deepEqual(planSave([c("alex", "pw")], "alex", "pw"), NONE);
  // ... even when another login under that name has a different password.
  assert.deepEqual(planSave([c("alex", "old"), c("alex", "pw")], "alex", "pw"), NONE);
  // ... and when the login that already has it is read-only.
  assert.deepEqual(planSave([ro("alex", "pw")], "alex", "pw"), NONE);
});

test("same user name, different password: update that login", () => {
  const a = c("alex", "old");
  const plan = planSave([c("sam", "x"), a], "alex", "new");
  assert.deepEqual([plan.action, plan.reason, plan.target], ["update", "same", a.id]);
});

test("user names compare trimmed and without case", () => {
  const a = c("Alex.Morgan@Example.com ", "old");
  assert.equal(planSave([a], "  alex.morgan@example.COM", "new").target, a.id);
  assert.deepEqual(planSave([a], "ALEX.MORGAN@EXAMPLE.COM", "old"), NONE);
});

test("only the user name was saved (empty password): update it", () => {
  const a = c("alex", "");
  const plan = planSave([a], "alex", "pw");
  assert.deepEqual([plan.action, plan.target], ["update", a.id]);
});

test("same user name only in a read-only vault: nothing to offer", () => {
  assert.deepEqual(planSave([ro("alex", "old")], "alex", "new"), NONE);
  // A writable login under another name doesn't change that.
  assert.deepEqual(planSave([ro("alex", "old"), c("sam", "x")], "alex", "new"), NONE);
});

test("same user name, read-only and writable copies: the writable one is updated", () => {
  const w = c("alex", "old");
  assert.equal(planSave([ro("alex", "older"), w], "alex", "new").target, w.id);
});

test("several logins under the same user name: the first writable one, in matching order", () => {
  const first = c("alex", "one");
  assert.equal(planSave([first, c("alex", "two")], "alex", "new").target, first.id);
});

// ------------------------------------------------------------------ 2. new user name

test("only a password was saved (empty user name): update it with the typed user name", () => {
  const blank = c("", "pw");
  const plan = planSave([blank], "alex", "pw");
  // An update even though the password is unchanged: the user name gets filled in.
  assert.deepEqual([plan.action, plan.reason, plan.target], ["update", "blank", blank.id]);
  assert.deepEqual(planSave([blank], "alex", "other").target, blank.id);
});

test("several empty-user-name logins: the one with this password, else the first", () => {
  const a = c("", "one");
  const b = c("  ", "two");
  assert.equal(planSave([a, b], "alex", "two").target, b.id);
  assert.equal(planSave([a, b], "alex", "three").target, a.id);
});

test("an empty-user-name login in a read-only vault is not a target: create", () => {
  const plan = planSave([ro("", "pw")], "alex", "pw");
  assert.deepEqual([plan.action, plan.target, plan.targets], ["create", NEW_LOGIN, []]);
});

test("new user name, no empty-user-name login: create", () => {
  const sam = c("sam", "x");
  const plan = planSave([sam], "alex", "pw");
  assert.deepEqual([plan.action, plan.target], ["create", NEW_LOGIN]);
  // The other login is still offered under "Save in".
  assert.deepEqual(plan.targets, [{ id: sam.id, name: sam.name, username: "sam" }]);
});

test("no login for the site: create", () => {
  assert.deepEqual(planSave([], "alex", "pw"), { action: "create", target: NEW_LOGIN, targets: [] });
});

// ------------------------------------------------------------------ 3. no user name on the page

test("no user name, the password is already saved for the site: nothing to offer", () => {
  assert.deepEqual(planSave([c("alex", "pw")], "", "pw"), NONE);
  assert.deepEqual(planSave([c("alex", "x"), ro("sam", "pw")], "  ", "pw"), NONE);
});

test("no user name, exactly one writable login: update its password, keep its user name", () => {
  const a = c("alex", "old");
  const plan = planSave([a], "", "new");
  assert.deepEqual([plan.action, plan.reason, plan.target], ["update", "only", a.id]);
  // Read-only logins for the site don't count.
  assert.equal(planSave([ro("sam", "x"), a], "", "new").target, a.id);
});

test("no user name, several writable logins (or none): create", () => {
  assert.equal(planSave([c("alex", "a"), c("sam", "b")], "", "new").action, "create");
  assert.equal(planSave([ro("alex", "a")], "", "new").action, "create");
  assert.equal(planSave([], "", "new").action, "create");
});

test("no user name, a login saved with only a password: update it (same empty user name)", () => {
  const blank = c("", "old");
  assert.equal(planSave([blank, c("alex", "a")], "", "new").target, blank.id);
  assert.deepEqual(planSave([blank], "", "old"), NONE);
  assert.deepEqual(planSave([ro("", "old")], "", "new"), NONE);
});

// ------------------------------------------------------------------ targets, answers, applying

test("an empty password is never saved", () => {
  assert.deepEqual(planSave([c("alex", "old")], "alex", ""), NONE);
});

test("targets: the user's own writable logins, in order, without passwords", () => {
  const a = c("alex", "one");
  const b = ro("sam", "two");
  const d = c("", "three");
  const plan = planSave([a, b, shared("pat", "four"), d], "kim", "pw");
  assert.deepEqual(plan.targets, [
    { id: a.id, name: a.name, username: "alex" },
    { id: d.id, name: d.name, username: "" },
  ]);
  assert.ok(!JSON.stringify(plan).includes("three"));
});

test("chosenTarget: only this save's own targets or New login, and only when the prompt says which", () => {
  const plan = { target: "a", targets: [{ id: "a", name: "A", username: "" }, { id: "b", name: "B", username: "x" }] };
  // No silent default: what is applied is what the prompt displayed.
  assert.equal(chosenTarget(plan, undefined), null);
  assert.equal(chosenTarget(plan, "a"), "a");
  assert.equal(chosenTarget(plan, "b"), "b");
  assert.equal(chosenTarget(plan, NEW_LOGIN), NEW_LOGIN);
  assert.equal(chosenTarget(plan, "someone-elses-item"), null);
  assert.equal(chosenTarget(plan, 7), null);
  assert.equal(chosenTarget(plan, null), null);
  assert.equal(chosenTarget({ target: NEW_LOGIN, targets: [] }, "a"), null);
});

test("applyToLogin: password always, user name only when one was typed, the rest untouched", () => {
  const login = { username: "alex", password: "old", urls: [{ url: "https://example.com", match: "default" }], totp: "JBSW", passkeys: [] };
  assert.deepEqual(applyToLogin(login, "", "new"), { ...login, password: "new" });
  assert.deepEqual(applyToLogin(login, "  ", "new"), { ...login, password: "new" });
  assert.deepEqual(applyToLogin({ ...login, username: "" }, " kim ", "new"), { ...login, username: "kim", password: "new" });
  assert.equal(login.password, "old");
});

test("describeSave names what will be saved", () => {
  const text = (parts) => parts.map((p) => (typeof p === "string" ? p : p.strong)).join("");
  const t = (username) => ({ id: "x", name: "Example", username });
  assert.equal(text(describeSave(undefined, "alex", "example.com")), "Saves alex and the password for example.com as a new login.");
  assert.equal(text(describeSave(undefined, "", "example.com")), "Saves the password for example.com as a new login, without a user name.");
  assert.equal(text(describeSave(t(""), "alex", "example.com")), "Adds the user name alex and updates the password.");
  assert.equal(text(describeSave(t("Alex"), "alex", "example.com")), "Updates the password for Alex.");
  assert.equal(text(describeSave(t("sam"), "alex", "example.com")), "Changes the user name from sam to alex and updates the password.");
  assert.equal(text(describeSave(t("sam"), "", "example.com")), "Updates the password for sam.");
  assert.equal(text(describeSave(t(""), "", "example.com")), "Updates the password. The login has no user name.");
});

// ------------------------------------------------------------------ shared vaults (revision 2)
// Anyone on the server can share a vault with the user (with write access) and plant a login in it.

test("planted blank-user-name login in a shared vault: never the update target, never listed (rule 2)", () => {
  const planted = shared("", "anything");
  const plan = planSave([planted], "alex", "my-password");
  assert.deepEqual([plan.action, plan.target, plan.targets], ["create", NEW_LOGIN, []]);
  // Not even when its password is the one that was typed.
  assert.deepEqual(planSave([shared("", "my-password")], "alex", "my-password"), { action: "create", target: NEW_LOGIN, targets: [] });
  // With an own blank login next to it, the own one is completed and the planted one stays out of the list.
  const mine = c("", "old");
  const both = planSave([planted, mine], "alex", "my-password");
  assert.deepEqual([both.action, both.reason, both.target], ["update", "blank", mine.id]);
  assert.deepEqual(both.targets.map((t) => t.id), [mine.id]);
  assert.equal(chosenTarget(both, planted.id), null);
});

test("planted login in a shared vault as the site's only login: not updated on a password-only step (rule 3)", () => {
  const planted = shared("someone", "anything");
  const plan = planSave([planted], "", "my-password");
  assert.deepEqual([plan.action, plan.target, plan.targets], ["create", NEW_LOGIN, []]);
  // It doesn't count towards "exactly one" either: the user's own single login is still the target.
  const mine = c("alex", "old");
  const both = planSave([planted, mine], "", "my-password");
  assert.deepEqual([both.action, both.reason, both.target], ["update", "only", mine.id]);
  assert.deepEqual(both.targets.map((t) => t.id), [mine.id]);
  // Two own logins: nothing is guessed.
  assert.equal(planSave([planted, mine, c("sam", "x")], "", "my-password").action, "create");
});

test("planted blank-user-name login, password-only step: an empty user name is no match for a shared login", () => {
  // Addendum A: with nothing typed, "the same (empty) user name" proves nothing about whose login it is.
  const planted = shared("", "anything");
  assert.deepEqual(planSave([planted], "", "my-password"), { action: "create", target: NEW_LOGIN, targets: [] });
  // The user's own blank login is still the match, and the planted one is not listed.
  const mine = c("", "old");
  const plan = planSave([planted, mine], "", "my-password");
  assert.deepEqual([plan.action, plan.reason, plan.target], ["update", "same", mine.id]);
  assert.deepEqual(plan.targets.map((t) => t.id), [mine.id]);
  // Their own single named login is the "only" one, whatever was planted.
  const named = c("alex", "old");
  const only = planSave([planted, named], "", "my-password");
  assert.deepEqual([only.action, only.reason, only.target], ["update", "only", named.id]);
  // "Already saved" still looks at every login, so nothing is offered twice.
  assert.deepEqual(planSave([shared("", "my-password")], "", "my-password"), NONE);
});

test("shared-vault login with the same user name: rule 1 still updates it, listed first with its vault's name", () => {
  const team = shared("alex", "old", { vault: "Team" });
  const mine = c("sam", "x");
  const plan = planSave([mine, team], "Alex", "new");
  assert.deepEqual([plan.action, plan.reason, plan.target], ["update", "same", team.id]);
  assert.deepEqual(plan.targets, [
    { id: team.id, name: team.name, username: "alex", vault: "Team" },
    { id: mine.id, name: mine.name, username: "sam" },
  ]);
  assert.equal(chosenTarget(plan, team.id), team.id);
  // Same password already there, or read-only: nothing to offer, as before.
  assert.deepEqual(planSave([shared("alex", "new")], "alex", "new"), NONE);
  assert.deepEqual(planSave([sharedRo("alex", "old")], "alex", "new"), NONE);
  // An own login under that name wins when it comes first in matching order.
  const own = c("alex", "old");
  assert.equal(planSave([own, team], "alex", "new").target, own.id);
});

test("other shared-vault logins are never offered under Save in", () => {
  const plan = planSave([shared("pat", "x"), shared("", "y"), sharedRo("kim", "z")], "alex", "pw");
  assert.deepEqual(plan, { action: "create", target: NEW_LOGIN, targets: [] });
});

test("a shared vault without a name still shows as shared", () => {
  const s1 = shared("alex", "old", { vault: "" });
  assert.equal(planSave([s1], "alex", "new").targets[0].vault, "Shared vault");
});

test("reason tells callers without their own prompt what must not be applied silently", () => {
  // The extension always shows its prompt; clients that can save silently must turn an "only" update into a prompt or a new login.
  const silentOk = (plan) => plan.action !== "update" || plan.reason !== "only";
  assert.equal(silentOk(planSave([c("alex", "old")], "alex", "new")), true); // same
  assert.equal(silentOk(planSave([c("", "old")], "alex", "new")), true); // blank
  assert.equal(silentOk(planSave([c("alex", "old")], "", "new")), false); // only
  assert.equal(silentOk(planSave([], "", "new")), true); // create
});

test("describeSave calls out a shared vault", () => {
  const text = (parts) => parts.map((p) => (typeof p === "string" ? p : p.strong)).join("");
  assert.equal(text(describeSave({ id: "x", name: "Example", username: "alex", vault: "Team" }, "alex", "example.com")), "Updates the password for alex. Members of the shared vault Team can see it.");
});

// ------------------------------------------------------------------ runner

let failed = 0;
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL - ${name}\n${e?.stack ?? e}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exitCode = failed ? 1 : 0;
