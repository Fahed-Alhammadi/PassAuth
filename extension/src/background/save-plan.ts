/**
 * The save rule: what to do with a user name and password the user just
 * submitted on a page that already has (or doesn't have) logins in the vault.
 * Pure (no chrome, no vault), unit-tested in test/save-plan.test.mjs.
 */

/** Save target meaning "create a new login" (never an item id: those are UUIDs). */
export const NEW_LOGIN = "new";

/** A vault login that matches the page, in the matching function's order. */
export interface SaveCandidate {
  id: string;
  name: string;
  username: string;
  password: string;
  /** In a vault the user can edit. */
  writable: boolean;
  /** In the user's own vault (wrapped with their account key), not one somebody shared with them. */
  personal: boolean;
  /** Name of the vault, shown when it is a shared one. */
  vault?: string;
}

/** A login the prompt offers under "Save in". Never carries a password. */
export interface SaveTarget {
  id: string;
  name: string;
  username: string;
  /** Set when the login lives in a shared vault: that vault's name. */
  vault?: string;
}

/**
 * Which rule chose the login to update: `same` user name, the user's own
 * `blank`-user-name login, or their `only` login for the site. Clients that can
 * save without showing their own prompt must not apply an `only` update silently.
 */
export type SaveReason = "same" | "blank" | "only";

export type SavePlan =
  | { action: "none" }
  /** `targets`: the logins the user may pick instead of a new one. */
  | { action: "create"; target: typeof NEW_LOGIN; targets: SaveTarget[] }
  /** `target`: the preselected login. */
  | { action: "update"; reason: SaveReason; target: string; targets: SaveTarget[] };

const norm = (s: string) => s.trim().toLowerCase();

/**
 * The default plan for the typed user name (may be empty: the page showed no
 * user-name field) and password, given the logins that match the page.
 *
 * Anyone on the server can share a vault with the user and put a login for a
 * site in it. Such a login is only ever updated when it already has the very
 * user name that was typed (rule 1); the rules that guess (2 and 3) and the
 * "Save in" list use the user's own logins only, so what is typed can't be
 * steered into somebody else's vault.
 */
export function planSave(candidates: SaveCandidate[], typedUser: string, password: string): SavePlan {
  if (!password) return { action: "none" };
  const user = norm(typedUser);
  const asTarget = (c: SaveCandidate): SaveTarget => ({ id: c.id, name: c.name, username: c.username, ...(c.personal ? {} : { vault: c.vault || "Shared vault" }) });
  const own = candidates.filter((c) => c.writable && c.personal);
  const targets = own.map(asTarget);
  const create: SavePlan = { action: "create", target: NEW_LOGIN, targets };

  // 1. Logins saved under this very user name (for an empty one: logins saved with only a password).
  // A shared-vault login counts only when a user name was typed and it has that exact name: an empty
  // user name matches any login saved without one, which is exactly what somebody could plant.
  const same = candidates.filter((c) => norm(c.username) === user);
  if (same.some((c) => c.password === password)) return { action: "none" };
  const mine = user ? same : same.filter((c) => c.personal);
  if (mine.length) {
    const first = mine.find((c) => c.writable);
    if (!first) return { action: "none" };
    // A shared-vault login is listed only here, as the selection, so the prompt can show it (with its vault's name).
    return { action: "update", reason: "same", target: first.id, targets: first.personal ? targets : [asTarget(first), ...targets] };
  }

  // 2. A new user name: complete one of the user's own logins that was saved with only a password, else it is a new login.
  if (user) {
    const blank = own.filter((c) => !norm(c.username));
    const pick = blank.find((c) => c.password === password) ?? blank[0];
    return pick ? { action: "update", reason: "blank", target: pick.id, targets } : create;
  }

  // 3. No user name on the page: the password belongs to the user's only own login for the site, if there is exactly one.
  if (candidates.some((c) => c.password === password)) return { action: "none" };
  return own.length === 1 ? { action: "update", reason: "only", target: own[0].id, targets } : create;
}

/**
 * The target the prompt answered with, if this save offered it; anything else
 * (nothing, or an id that isn't in the pending save's own list) is refused
 * (`null`). What gets applied is what the prompt displayed, never a default
 * worked out again later.
 */
export function chosenTarget(plan: { targets: SaveTarget[] }, answer: unknown): string | null {
  if (answer === NEW_LOGIN) return NEW_LOGIN;
  return typeof answer === "string" && plan.targets.some((t) => t.id === answer) ? answer : null;
}

/** A login after the submitted credentials were saved into it: the password always, the user name only when one was typed. */
export function applyToLogin<T extends { username: string; password: string }>(login: T, typedUser: string, password: string): T {
  return { ...login, username: typedUser.trim() || login.username, password };
}

/** Text with emphasised values, for prompts that must never build HTML from page or vault data. */
export type TextPart = string | { strong: string };

/** What saving into `target` (undefined = a new login) will do, in a sentence; a shared vault is called out. */
export function describeSave(target: SaveTarget | undefined, typedUser: string, host: string): TextPart[] {
  const user = typedUser.trim();
  if (!target) {
    return user ? ["Saves ", { strong: user }, ` and the password for ${host} as a new login.`] : [`Saves the password for ${host} as a new login, without a user name.`];
  }
  const shared: TextPart[] = target.vault ? [" Members of the shared vault ", { strong: target.vault }, " can see it."] : [];
  const saved = target.username.trim();
  if (!user) return saved ? ["Updates the password for ", { strong: saved }, ".", ...shared] : ["Updates the password. The login has no user name.", ...shared];
  if (!saved) return ["Adds the user name ", { strong: user }, " and updates the password.", ...shared];
  if (norm(saved) === norm(user)) return ["Updates the password for ", { strong: saved }, ".", ...shared];
  return ["Changes the user name from ", { strong: saved }, " to ", { strong: user }, " and updates the password.", ...shared];
}
