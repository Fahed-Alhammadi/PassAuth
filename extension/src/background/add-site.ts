/**
 * "Add this site to a login": one account that signs in on several sites (a mail login also used for a developer
 * console on another domain). The page's address is added as one more website of a login the user picks, so that
 * login is suggested and filled there from now on instead of a second copy being saved.
 *
 * Only PassAuth's own pages ask for it (the popup's picker, the save prompt frame): a website never can. Only logins
 * the user can edit are offered, and the address added is the page's origin with match "default" (the user's own
 * matching setting), the same as a login saved from the page.
 */
import type { Item, LoginUrl } from "@web/lib/types";
import { AppError, NOT_ALLOWED, NOT_FOUND, notAllowed } from "../shared/errors";
import type { ItemSummary } from "../shared/types";
import { initCore } from "./core";
import { matchesUrl, parse } from "./site";
import { getSettings } from "./storage";
import * as vault from "./vault";

/** The page's origin when it is an http(s) page, else null. */
export function siteOrigin(url: string): string | null {
  const page = parse(url);
  return page && /^https?:$/.test(page.protocol) && page.hostname ? page.origin : null;
}

/** Does one of `urls` already match the page (with the user's default matching)? */
async function alreadyMatches(urls: readonly LoginUrl[], url: string, personal: boolean): Promise<boolean> {
  await initCore();
  const { defaultMatch } = await getSettings();
  return urls.some((u) => matchesUrl(url, u, defaultMatch, personal));
}

/** The login with the page's origin added to its websites (`login` must be set). */
export function withSite(item: Item, origin: string): Item {
  const login = item.login!;
  return { ...item, login: { ...login, urls: [...login.urls, { url: origin, match: "default" }] } };
}

/** Logins the page's address can be added to: the user can edit them and none of their websites matches the page yet. Own vaults first. */
export async function addSiteTargets(url: string): Promise<ItemSummary[]> {
  if (!siteOrigin(url)) return [];
  const out: vault.Entry[] = [];
  for (const e of vault.allEntries()) {
    if (!e.item.login || !vault.canWrite(e)) continue;
    if (await alreadyMatches(e.item.login.urls, url, vault.isPersonal(e))) continue;
    out.push(e);
  }
  out.sort((a, b) => Number(vault.isPersonal(b)) - Number(vault.isPersonal(a)));
  return out.map(vault.summarize);
}

/** Add the page's address to login `id`. Returns false when the login already matched the page (nothing changed). */
export async function addSite(id: string, url: string): Promise<boolean> {
  const origin = siteOrigin(url);
  if (!origin) throw notAllowed();
  const e = vault.getEntry(id);
  if (!e?.item.login) throw new AppError(NOT_FOUND, "Login not found.");
  if (!vault.canWrite(e)) throw new AppError(NOT_ALLOWED, "You can only view this login, so no website can be added to it.");
  if (await alreadyMatches(e.item.login.urls, url, vault.isPersonal(e))) return false;
  await vault.updateItem(e, withSite(e.item, origin));
  return true;
}
