/**
 * The match index: for each login of an unlocked account, its id, its websites and match rules, and whether it is
 * in the user's own vault, and how many cards and identities it has. No names, user names, passwords or codes. It lives in session storage (`index:<account>`,
 * extension-private, memory-only) next to the unlocked keys and goes with them, so after a service-worker restart the
 * toolbar badge and the inline menu's icon can count the logins for a page without opening the vault (no key
 * restore, no decrypting every item). Anything that shows or fills a login still decrypts.
 */
import type { LoginUrl } from "@web/lib/types";
import { type DefaultMatch, matchingEntries } from "./site";
import { scratch } from "./storage";

export interface IndexedLogin {
  id: string;
  urls: LoginUrl[];
  /** In one of the user's own vaults: only then do its regular expressions count (site.ts `allowRegex`). */
  personal: boolean;
}

export interface MatchIndex {
  revision: number;
  logins: IndexedLogin[];
  /** How many cards and identities the account has (the right-click menu lists them; counts only). Unknown in older indexes. */
  cards?: number;
  identities?: number;
}

const key = (accountId: string) => `index:${accountId}`;

const isIndex = (v: unknown): v is MatchIndex => {
  const i = v as Partial<MatchIndex> | null;
  return !!i && typeof i.revision === "number" && Array.isArray(i.logins);
};

export const matchIndex = {
  async get(accountId: string): Promise<MatchIndex | null> {
    const v = await scratch.get<unknown>(key(accountId));
    return isIndex(v) ? v : null;
  },
  set: (accountId: string, index: MatchIndex) => scratch.set(key(accountId), index),
  clear: (accountIds: string[]) => scratch.remove(accountIds.map(key)),
};

/** The ids of the indexed logins whose websites match `url` (the same rule as matching decrypted items; the core must be loaded). */
export function matchingIds(index: MatchIndex, url: string, defaultMatch: DefaultMatch): string[] {
  return matchingEntries(
    url,
    index.logins,
    (l) => l.urls,
    (l) => l.personal,
    defaultMatch,
  ).map((l) => l.id);
}
