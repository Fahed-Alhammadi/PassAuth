/** Which logins belong to a page (the core's matching: site.ts). */
import { loggedAs } from "../shared/log";
import { initCore } from "./core";
import { matchingIds } from "./match-index";
import { matchingEntries } from "./site";
import { getSettings } from "./storage";
import * as vault from "./vault";

/**
 * Logins whose websites match `url` (the vault must be open). A regular-expression website counts only in the user's
 * own vaults: one from a shared vault was written by somebody else, and patterns run on every page the user visits.
 */
export async function matching(url: string): Promise<vault.Entry[]> {
  await initCore();
  const { defaultMatch } = await getSettings();
  return matchingEntries(
    url,
    vault.allEntries().filter((e) => e.item.login),
    (e) => e.item.login?.urls ?? [],
    (e) => vault.isPersonal(e),
    defaultMatch,
  );
}

/**
 * How many logins match `url`, or null while PassAuth is locked. From the match index when there is one (no
 * decrypting after a service-worker restart); otherwise the vault is opened.
 */
export async function countMatching(url: string): Promise<number | null> {
  await initCore();
  const index = await vault.unlockedIndex().catch(loggedAs(null, "Reading the match index"));
  if (index) return matchingIds(index, url, (await getSettings()).defaultMatch).length;
  if (!(await vault.ensureUnlocked().catch(loggedAs(false, "Opening the vault")))) return null;
  return (await matching(url)).length;
}
