// The save rule (the core's, through src/background/site.ts): update an existing login instead of saving a duplicate.
// And what the prompt says about each choice (src/shared/save-text.ts).

import { expect, test } from "vitest";
import { applyToLogin, chosenTarget, NEW_LOGIN, planSave, type SaveCandidate, type SavePlan, type SaveTarget } from "../src/background/site";
import { describeSave, sharedWarning, type TextPart } from "../src/shared/save-text";

let n = 0;
/** A login that matches the page. */
const c = (username: string, password: string, extra: Partial<SaveCandidate> = {}): SaveCandidate => ({
  id: `id-${++n}`,
  name: `Login ${n}`,
  username,
  password,
  writable: true,
  personal: true,
  ...extra,
});
/** In the user's own vault, but read-only (cannot normally happen; the rule must still not write to it). */
const ro = (username: string, password: string) => c(username, password, { writable: false });
/** In a vault somebody shared with the user, with write access: what an attacker can plant. */
const shared = (username: string, password: string, extra: Partial<SaveCandidate> = {}) => c(username, password, { personal: false, vault: "Family", ...extra });
/** Shared and read-only. */
const sharedRo = (username: string, password: string) => shared(username, password, { writable: false });
const NONE: SavePlan = { action: "none" };
/** The parts of a plan most tests compare. */
const head = (plan: SavePlan) => [plan.action, plan.action === "update" ? plan.reason : undefined, plan.action === "none" ? undefined : plan.target];
const targetOf = (plan: SavePlan) => (plan.action === "none" ? undefined : plan.target);
const targetsOf = (plan: SavePlan): SaveTarget[] => (plan.action === "none" ? [] : plan.targets);
const text = (parts: TextPart[]) => parts.map((p) => (typeof p === "string" ? p : p.strong)).join("");

// ------------------------------------------------------------------ 1. same user name

test("same user name, same password: nothing to offer", () => {
  expect(planSave([c("alex", "pw")], "alex", "pw")).toStrictEqual(NONE);
  // ... even when another login under that name has a different password.
  expect(planSave([c("alex", "old"), c("alex", "pw")], "alex", "pw")).toStrictEqual(NONE);
  // ... and when the login that already has it is read-only.
  expect(planSave([ro("alex", "pw")], "alex", "pw")).toStrictEqual(NONE);
});

test("same user name, different password: update that login", () => {
  const a = c("alex", "old");
  const plan = planSave([c("sam", "x"), a], "alex", "new");
  expect(head(plan)).toStrictEqual(["update", "same", a.id]);
});

test("user names compare trimmed and without case", () => {
  const a = c("Alex.Morgan@Example.com ", "old");
  expect(targetOf(planSave([a], "  alex.morgan@example.COM", "new"))).toBe(a.id);
  expect(planSave([a], "ALEX.MORGAN@EXAMPLE.COM", "old")).toStrictEqual(NONE);
});

test("only the user name was saved (empty password): update it", () => {
  const a = c("alex", "");
  const plan = planSave([a], "alex", "pw");
  expect([plan.action, targetOf(plan)]).toStrictEqual(["update", a.id]);
});

test("same user name only in a read-only login: a new login is offered instead (rule 1 never writes to it)", () => {
  // Was "nothing to offer": the typed password worked, so it is saved in the user's own vault rather than lost.
  expect(planSave([ro("alex", "old")], "alex", "new")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
  // A writable login under another name is offered under "Save in", not preselected.
  const sam = c("sam", "x");
  expect(planSave([ro("alex", "old"), sam], "alex", "new")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [{ id: sam.id, name: sam.name, username: "sam" }] });
  // Already saved there with this password: nothing.
  expect(planSave([ro("alex", "new")], "alex", "new")).toStrictEqual(NONE);
});

test("same user name, read-only and writable copies: the writable one is updated", () => {
  const w = c("alex", "old");
  expect(targetOf(planSave([ro("alex", "older"), w], "alex", "new"))).toBe(w.id);
});

test("several logins under the same user name: the first writable one, in matching order", () => {
  const first = c("alex", "one");
  expect(targetOf(planSave([first, c("alex", "two")], "alex", "new"))).toBe(first.id);
});

// ------------------------------------------------------------------ 2. new user name

test("only a password was saved (empty user name): update it with the typed user name", () => {
  const blank = c("", "pw");
  const plan = planSave([blank], "alex", "pw");
  // An update even though the password is unchanged: the user name gets filled in.
  expect(head(plan)).toStrictEqual(["update", "blank", blank.id]);
  expect(targetOf(planSave([blank], "alex", "other"))).toBe(blank.id);
});

test("several empty-user-name logins: the one with this password, else the first", () => {
  const a = c("", "one");
  const b = c("  ", "two");
  expect(targetOf(planSave([a, b], "alex", "two"))).toBe(b.id);
  expect(targetOf(planSave([a, b], "alex", "three"))).toBe(a.id);
});

test("an empty-user-name login in a read-only vault is not a target: create", () => {
  const plan = planSave([ro("", "pw")], "alex", "pw");
  expect([plan.action, targetOf(plan), targetsOf(plan)]).toStrictEqual(["create", NEW_LOGIN, []]);
});

test("new user name, no empty-user-name login: create", () => {
  const sam = c("sam", "x");
  const plan = planSave([sam], "alex", "pw");
  expect([plan.action, targetOf(plan)]).toStrictEqual(["create", NEW_LOGIN]);
  // The other login is still offered under "Save in".
  expect(targetsOf(plan)).toStrictEqual([{ id: sam.id, name: sam.name, username: "sam" }]);
});

test("no login for the site: create", () => {
  expect(planSave([], "alex", "pw")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
});

// ------------------------------------------------------------------ 3. no user name on the page

test("no user name, the password is already saved for the site: nothing to offer", () => {
  expect(planSave([c("alex", "pw")], "", "pw")).toStrictEqual(NONE);
  expect(planSave([c("alex", "x"), ro("sam", "pw")], "  ", "pw")).toStrictEqual(NONE);
});

test("no user name, exactly one writable login: update its password, keep its user name", () => {
  const a = c("alex", "old");
  const plan = planSave([a], "", "new");
  expect(head(plan)).toStrictEqual(["update", "only", a.id]);
  // Read-only logins for the site don't count.
  expect(targetOf(planSave([ro("sam", "x"), a], "", "new"))).toBe(a.id);
});

test("no user name, several writable logins (or none): create", () => {
  expect(planSave([c("alex", "a"), c("sam", "b")], "", "new").action).toBe("create");
  expect(planSave([ro("alex", "a")], "", "new").action).toBe("create");
  expect(planSave([], "", "new").action).toBe("create");
});

test("no user name, a login saved with only a password: update it (same empty user name)", () => {
  const blank = c("", "old");
  expect(targetOf(planSave([blank, c("alex", "a")], "", "new"))).toBe(blank.id);
  expect(planSave([blank], "", "old")).toStrictEqual(NONE);
  // Read-only (rule 1 never writes to it): the password is offered as a new login instead (was "nothing").
  expect(planSave([ro("", "old")], "", "new")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
});

// ------------------------------------------------------------------ targets, answers, applying

test("an empty password is never saved", () => {
  expect(planSave([c("alex", "old")], "alex", "")).toStrictEqual(NONE);
});

test("targets: the user's own writable logins, in order, without passwords", () => {
  const a = c("alex", "one");
  const b = ro("sam", "two");
  const d = c("", "three");
  const plan = planSave([a, b, shared("pat", "four"), d], "kim", "pw");
  expect(targetsOf(plan)).toStrictEqual([
    { id: a.id, name: a.name, username: "alex" },
    { id: d.id, name: d.name, username: "" },
  ]);
  expect(JSON.stringify(plan).includes("three")).toBe(false);
});

test("chosenTarget: only this save's own targets or New login, and only when the prompt says which", () => {
  const plan = {
    target: "a",
    targets: [
      { id: "a", name: "A", username: "" },
      { id: "b", name: "B", username: "x" },
    ],
  };
  // No silent default: what is applied is what the prompt displayed.
  expect(chosenTarget(plan, undefined)).toBe(null);
  expect(chosenTarget(plan, "a")).toBe("a");
  expect(chosenTarget(plan, "b")).toBe("b");
  expect(chosenTarget(plan, NEW_LOGIN)).toBe(NEW_LOGIN);
  expect(chosenTarget(plan, "someone-elses-item")).toBe(null);
  expect(chosenTarget(plan, 7)).toBe(null);
  expect(chosenTarget(plan, null)).toBe(null);
  expect(chosenTarget({ targets: [] }, "a")).toBe(null);
});

test("applyToLogin: password always, user name only when one was typed, the rest untouched", () => {
  const login = { username: "alex", password: "old", urls: [{ url: "https://example.com", match: "default" }], totp: "JBSW", passkeys: [] };
  expect(applyToLogin(login, "", "new")).toStrictEqual({ ...login, password: "new" });
  expect(applyToLogin(login, "  ", "new")).toStrictEqual({ ...login, password: "new" });
  expect(applyToLogin({ ...login, username: "" }, " kim ", "new")).toStrictEqual({ ...login, username: "kim", password: "new" });
  expect(login.password).toBe("old");
});

test("describeSave names what will be saved", () => {
  const t = (username: string) => ({ id: "x", name: "Example", username });
  expect(text(describeSave(undefined, "alex", "example.com"))).toBe("Saves alex and the password for example.com as a new login.");
  expect(text(describeSave(undefined, "", "example.com"))).toBe("Saves the password for example.com as a new login, without a user name.");
  expect(text(describeSave(t(""), "alex", "example.com"))).toBe("Adds the user name alex and updates the password.");
  expect(text(describeSave(t("Alex"), "alex", "example.com"))).toBe("Updates the password for Alex.");
  expect(text(describeSave(t("sam"), "alex", "example.com"))).toBe("Changes the user name from sam to alex and updates the password.");
  expect(text(describeSave(t("sam"), "", "example.com"))).toBe("Updates the password for sam.");
  expect(text(describeSave(t(""), "", "example.com"))).toBe("Updates the password. The login has no user name.");
});

// ------------------------------------------------------------------ shared vaults (revision 2)
// Anyone on the server can share a vault with the user (with write access) and plant a login in it.

test("planted blank-user-name login in a shared vault: never the update target, never listed (rule 2)", () => {
  const planted = shared("", "anything");
  const plan = planSave([planted], "alex", "my-password");
  expect([plan.action, targetOf(plan), targetsOf(plan)]).toStrictEqual(["create", NEW_LOGIN, []]);
  // Not even when its password is the one that was typed.
  expect(planSave([shared("", "my-password")], "alex", "my-password")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
  // With an own blank login next to it, the own one is completed and the planted one stays out of the list.
  const mine = c("", "old");
  const both = planSave([planted, mine], "alex", "my-password");
  expect(head(both)).toStrictEqual(["update", "blank", mine.id]);
  expect(targetsOf(both).map((t) => t.id)).toStrictEqual([mine.id]);
  expect(chosenTarget({ targets: targetsOf(both) }, planted.id)).toBe(null);
});

test("planted login in a shared vault as the site's only login: not updated on a password-only step (rule 3)", () => {
  const planted = shared("someone", "anything");
  const plan = planSave([planted], "", "my-password");
  expect([plan.action, targetOf(plan), targetsOf(plan)]).toStrictEqual(["create", NEW_LOGIN, []]);
  // It doesn't count towards "exactly one" either: the user's own single login is still the target.
  const mine = c("alex", "old");
  const both = planSave([planted, mine], "", "my-password");
  expect(head(both)).toStrictEqual(["update", "only", mine.id]);
  expect(targetsOf(both).map((t) => t.id)).toStrictEqual([mine.id]);
  // Two own logins: nothing is guessed.
  expect(planSave([planted, mine, c("sam", "x")], "", "my-password").action).toBe("create");
});

test("planted blank-user-name login, password-only step: an empty user name is no match for a shared login", () => {
  // Addendum A: with nothing typed, "the same (empty) user name" proves nothing about whose login it is.
  const planted = shared("", "anything");
  expect(planSave([planted], "", "my-password")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
  // The user's own blank login is still the match, and the planted one is not listed.
  const mine = c("", "old");
  const plan = planSave([planted, mine], "", "my-password");
  expect(head(plan)).toStrictEqual(["update", "same", mine.id]);
  expect(targetsOf(plan).map((t) => t.id)).toStrictEqual([mine.id]);
  // Their own single named login is the "only" one, whatever was planted.
  const named = c("alex", "old");
  const only = planSave([planted, named], "", "my-password");
  expect(head(only)).toStrictEqual(["update", "only", named.id]);
  // "Already saved" still looks at every login, so nothing is offered twice.
  expect(planSave([shared("", "my-password")], "", "my-password")).toStrictEqual(NONE);
});

test("S1: a planted shared-vault login with the typed user name is never preselected", () => {
  // Anyone can add the user to a vault and plant a login under the victim's email: it must not collect the typed password.
  const planted = shared("alex@example.com", "old", { vault: "Team" });
  const plan = planSave([planted], "Alex@Example.com", "new");
  // No own login under that name: a new login in the personal vault is preselected …
  expect(head(plan)).toStrictEqual(["create", undefined, NEW_LOGIN]);
  // … and the shared one is an extra choice that names its vault.
  expect(targetsOf(plan)).toStrictEqual([{ id: planted.id, name: planted.name, username: "alex@example.com", vault: "Team" }]);
  // It is applied only when the prompt answers with it (the user picked it).
  expect(chosenTarget({ targets: targetsOf(plan) }, planted.id)).toBe(planted.id);
  expect(chosenTarget({ targets: targetsOf(plan) }, NEW_LOGIN)).toBe(NEW_LOGIN);
});

test("S1: the user's own login with the typed user name wins, wherever the shared one is in matching order", () => {
  const team = shared("alex", "old", { vault: "Team" });
  const mine = c("sam", "x");
  const own = c("alex", "older");
  for (const order of [
    [team, mine, own],
    [own, team, mine],
    [mine, own, team],
  ]) {
    const plan = planSave(order, "Alex", "new");
    expect(head(plan)).toStrictEqual(["update", "same", own.id]);
    // Own logins first (in matching order), the shared one last with its vault's name.
    expect(targetsOf(plan).at(-1)).toStrictEqual({ id: team.id, name: team.name, username: "alex", vault: "Team" });
    expect(
      targetsOf(plan)
        .filter((t) => !t.vault)
        .map((t) => t.id),
    ).toStrictEqual(order.filter((x) => x.personal).map((x) => x.id));
  }
});

test("S1: shared-vault logins with the typed user name: same password → nothing; read-only → not listed", () => {
  // Same password already there: nothing to offer, as before.
  expect(planSave([shared("alex", "new")], "alex", "new")).toStrictEqual(NONE);
  // Read-only: never a target; the password is offered as a new login of the user's own.
  expect(planSave([sharedRo("alex", "old")], "alex", "new")).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
  // Several writable shared ones: all listed (unselected), none preselected.
  const a = shared("alex", "1", { vault: "A" });
  const b = shared("alex", "2", { vault: "B" });
  const plan = planSave([a, b], "alex", "new");
  expect(targetOf(plan)).toBe(NEW_LOGIN);
  expect(targetsOf(plan).map((t) => [t.id, t.vault])).toStrictEqual([
    [a.id, "A"],
    [b.id, "B"],
  ]);
});

test("other shared-vault logins are never offered under Save in", () => {
  const plan = planSave([shared("pat", "x"), shared("", "y"), sharedRo("kim", "z")], "alex", "pw");
  expect(plan).toStrictEqual({ action: "create", target: NEW_LOGIN, targets: [] });
});

test("a shared vault without a name still shows as shared", () => {
  const s1 = shared("alex", "old", { vault: "" });
  expect(targetsOf(planSave([s1], "alex", "new"))[0]?.vault).toBe("Shared vault");
});

test("reason tells callers without their own prompt what must not be applied silently", () => {
  // The extension always shows its prompt; clients that can save silently must turn an "only" update into a prompt or a new login.
  const silentOk = (plan: SavePlan) => plan.action !== "update" || plan.reason !== "only";
  expect(silentOk(planSave([c("alex", "old")], "alex", "new"))).toBe(true); // same
  expect(silentOk(planSave([c("", "old")], "alex", "new"))).toBe(true); // blank
  expect(silentOk(planSave([c("alex", "old")], "", "new"))).toBe(false); // only
  expect(silentOk(planSave([], "", "new"))).toBe(true); // create
});

test("sharedWarning: only for a login in a shared vault, naming the vault", () => {
  expect(sharedWarning(undefined)).toBe(null);
  expect(sharedWarning({ id: "x", name: "Example", username: "alex" })).toBe(null);
  expect(text(sharedWarning({ id: "x", name: "Example", username: "alex", vault: "Team" })!)).toBe("Saving here shares this password with everyone in Team.");
  expect(text(sharedWarning({ id: "x", name: "Example", username: "alex", vault: "Team" }, "passkey")!)).toBe("Saving here shares this passkey with everyone in Team.");
  // The sentence about the change itself no longer repeats it.
  expect(text(describeSave({ id: "x", name: "Example", username: "alex", vault: "Team" }, "alex", "example.com"))).toBe("Updates the password for alex.");
});
