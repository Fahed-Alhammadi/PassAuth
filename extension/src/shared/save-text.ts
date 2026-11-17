/**
 * The words of the save prompt and the passkey window's "Save in" choice (the rule itself is the core's: site.ts
 * `planSave`, `passkeySaveTargets`). Pure: the prompt frame and the popup use it, and they never build HTML from page
 * or vault data — emphasised values travel as `{ strong }` parts.
 */
import type { AddSiteTarget, SaveTarget } from "./types";

/** Save target meaning "create a new login" (never an item id: those are UUIDs); the core's word for it. */
export const NEW_LOGIN = "new";

/** Text with emphasised values, for prompts that must never build HTML from page or vault data. */
export type TextPart = string | { strong: string };

const norm = (s: string) => s.trim().toLowerCase();

/** What saving into `target` (undefined = a new login) will do, in a sentence. */
export function describeSave(target: SaveTarget | undefined, typedUser: string, host: string): TextPart[] {
  const user = typedUser.trim();
  if (!target) {
    return user ? ["Saves ", { strong: user }, ` and the password for ${host} as a new login.`] : [`Saves the password for ${host} as a new login, without a user name.`];
  }
  const saved = target.username.trim();
  if (!user) return saved ? ["Updates the password for ", { strong: saved }, "."] : ["Updates the password. The login has no user name."];
  if (!saved) return ["Adds the user name ", { strong: user }, " and updates the password."];
  if (norm(saved) === norm(user)) return ["Updates the password for ", { strong: saved }, "."];
  return ["Changes the user name from ", { strong: saved }, " to ", { strong: user }, " and updates the password."];
}

/** The warning shown while a login in a shared vault is selected: everyone in that vault gets the password. */
export function sharedWarning(target: SaveTarget | undefined, what = "password"): TextPart[] | null {
  return target?.vault ? [`Saving here shares this ${what} with everyone in `, { strong: target.vault }, "."] : null;
}

/** What adding this site to a login for another site does. */
export function describeAddSite(target: AddSiteTarget, host: string): TextPart[] {
  return [`Adds ${host} to `, { strong: target.name }, ". Its user name and password stay the same, and it is suggested here from now on."];
}

/** Said while such a login is selected: only for a site of the same account. */
export function addSiteWarning(target: AddSiteTarget, host: string): TextPart[] {
  return target.site ? ["Only add it if ", { strong: host }, " uses the same account as ", { strong: target.site }, "."] : ["Only add it if this site uses the same account."];
}
