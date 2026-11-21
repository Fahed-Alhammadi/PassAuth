/**
 * Website matching (Password health): logins whose websites have their own match ("Base domain", "Host"…), so the
 * device's "Default URI match detection" setting never applies to them, and how they are set back to "Default".
 *
 * Pure and unit-tested (`matching.test.ts`): no React and no network. Callers pass in the core's `baseDomain` (the
 * full Public Suffix List, WASM) and, for `applyDefaultMatch`, the vault's own `updateItem`.
 *
 * Only logins the user can change are listed (a vault that takes the write, not in the trash, no offline change
 * waiting, not rolled back). "Regular expression" and "Never" are deliberate and left as they are.
 */
import type { Item, LoginUrl, UrlMatch } from "./types";

/** What the list reads from a vault entry (a `VaultEntry` fits). */
export interface MatchEntry {
  id: string;
  vaultId: string;
  revision: number;
  deletedAt: number | null;
  item: Item;
  /** The server sent an older version than this device saw: never changed here. */
  rollback?: boolean;
}

export interface MatchOptions {
  /** The core's `baseDomain`: the registrable domain of a host ("signin.apple.com" → "apple.com"), else the host. */
  baseDomain: (host: string) => string;
  /** Whether a vault takes this write: the user can edit it and it passed its checks. */
  writableVault: (vaultId: string) => boolean;
  /** Items with an offline change waiting: left out. */
  pending?: ReadonlySet<string>;
}

/** One login of a group, with only its websites in that group that have their own match. */
export interface MatchLogin<T extends MatchEntry = MatchEntry> {
  entry: T;
  urls: LoginUrl[];
}

export interface MatchGroup<T extends MatchEntry = MatchEntry> {
  /** The base domain (or app address) the websites share. */
  domain: string;
  logins: MatchLogin<T>[];
  /** How many websites of the group would change. */
  websites: number;
}

export interface MatchReport<T extends MatchEntry = MatchEntry> {
  groups: MatchGroup<T>[];
  /** Websites with "Regular expression" or "Never" in logins the user can change: left as they are. */
  left: number;
}

const LABELS: Record<UrlMatch, string> = {
  default: "Default",
  domain: "Base domain",
  host: "Host",
  starts_with: "Starts with",
  exact: "Exact",
  regex: "Regular expression",
  never: "Never",
};

/** The match as the login editor names it. */
export const matchLabel = (m: UrlMatch): string => LABELS[m] ?? m;

/** A match this tool sets to "Default". */
/**
 * Whether every website of a group is "Base domain": then "Default" can only narrow it (or keep it), whatever an
 * app's setting is. Groups with "Host", "Starts with" or "Exact" could be offered on more sites of the domain, so the
 * page starts them unchecked.
 */
export const onlyBaseDomain = (g: MatchGroup): boolean => g.logins.every((l) => l.urls.every((u) => u.match === "domain"));

export const qualifies = (m: UrlMatch): boolean => m === "domain" || m === "host" || m === "starts_with" || m === "exact";

const deliberate = (m: UrlMatch): boolean => m === "regex" || m === "never";

/**
 * The group of a saved address: the base domain of an http(s) address (an address without a scheme is https, as in
 * matching), else the address itself in lower case (app addresses). Null for an empty or unreadable address.
 */
export function urlGroup(raw: string, baseDomain: (host: string) => string): string | null {
  const s = typeof raw === "string" ? raw.trim() : "";
  if (!s) return null;
  let url: URL;
  try {
    url = new URL(s.includes("://") ? s : `https://${s}`);
  } catch {
    return null;
  }
  if (url.protocol === "https:" || url.protocol === "http:") {
    if (!url.hostname) return null;
    return baseDomain(url.hostname) || url.hostname;
  }
  return s.toLowerCase();
}

const eligible = (e: MatchEntry, opts: MatchOptions): boolean =>
  !!e.item?.login && e.deletedAt === null && !e.rollback && !opts.pending?.has(e.id) && opts.writableVault(e.vaultId);

const byName = (a: MatchLogin, b: MatchLogin): number =>
  (a.entry.item.name || "Untitled").localeCompare(b.entry.item.name || "Untitled", undefined, { sensitivity: "base" }) ||
  (a.entry.id < b.entry.id ? -1 : a.entry.id > b.entry.id ? 1 : 0);

/** The logins with websites that have their own match, grouped by base domain (sorted by domain, logins by name). */
export function findMatchGroups<T extends MatchEntry>(entries: readonly T[], opts: MatchOptions): MatchReport<T> {
  const groups = new Map<string, Map<string, MatchLogin<T>>>();
  let left = 0;
  for (const e of entries) {
    if (!eligible(e, opts)) continue;
    for (const u of e.item.login?.urls ?? []) {
      if (typeof u?.url !== "string" || !u.url.trim()) continue;
      if (deliberate(u.match)) {
        left++;
        continue;
      }
      if (!qualifies(u.match)) continue;
      const domain = urlGroup(u.url, opts.baseDomain);
      if (!domain) continue;
      let logins = groups.get(domain);
      if (!logins) groups.set(domain, (logins = new Map()));
      const one = logins.get(e.id);
      if (one) one.urls.push(u);
      else logins.set(e.id, { entry: e, urls: [u] });
    }
  }
  const out: MatchGroup<T>[] = [...groups.entries()].map(([domain, logins]) => {
    const list = [...logins.values()].sort(byName);
    return { domain, logins: list, websites: list.reduce((n, l) => n + l.urls.length, 0) };
  });
  out.sort((a, b) => a.domain.localeCompare(b.domain));
  return { groups: out, left };
}

/**
 * The item with every qualifying website in `domains` set to "Default"; everything else (other websites, unknown
 * fields) untouched. Null when nothing would change.
 */
export function withDefaultMatch(item: Item, domains: ReadonlySet<string>, baseDomain: (host: string) => string): Item | null {
  const login = item.login;
  if (!login) return null;
  let changed = false;
  const urls = login.urls.map((u) => {
    if (typeof u?.url !== "string" || !qualifies(u.match)) return u;
    const domain = urlGroup(u.url, baseDomain);
    if (!domain || !domains.has(domain)) return u;
    changed = true;
    return { ...u, match: "default" as const };
  });
  return changed ? { ...item, login: { ...login, urls } } : null;
}

/** Counts the websites `withDefaultMatch` changed. */
const changedCount = (before: Item, after: Item): number => after.login!.urls.filter((u, n) => u.match !== before.login!.urls[n]?.match).length;

export interface ApplyDeps<T extends MatchEntry> {
  /** The vault's `updateItem`: an ordinary edit. */
  update: (entry: T, item: Item) => Promise<void>;
  /** The login as the vault holds it now, or undefined when it is gone. */
  current: (id: string) => T | undefined;
  baseDomain: (host: string) => string;
  /** Called before each save. */
  progress?: (done: number, total: number) => void;
}

export const MATCH_CHANGED = "These logins changed since this list was made, so nothing was saved. Check the updated list and try again.";

/** Saving stopped part way: `done` logins were saved before the error. */
export class MatchIncomplete extends Error {
  constructor(
    readonly done: number,
    readonly cause?: unknown,
  ) {
    super(`${done === 1 ? "1 login was" : `${done} logins were`} changed, then saving stopped. Try again for the rest.`);
  }
}

/**
 * Set the qualifying websites of the chosen groups to "Default", one save per login. Nothing is written when any of
 * those logins changed since the list was made (MATCH_CHANGED). A failure after some saves throws `MatchIncomplete`.
 */
export async function applyDefaultMatch<T extends MatchEntry>(
  groups: readonly MatchGroup<T>[],
  domains: ReadonlySet<string>,
  deps: ApplyDeps<T>,
): Promise<{ logins: number; websites: number }> {
  const seen = new Map<string, T>();
  for (const g of groups) if (domains.has(g.domain)) for (const l of g.logins) seen.set(l.entry.id, l.entry);
  const targets = [...seen.values()];
  for (const e of targets) {
    const now = deps.current(e.id);
    if (!now || now.revision !== e.revision || now.deletedAt !== null || now.vaultId !== e.vaultId) throw new Error(MATCH_CHANGED);
  }
  let logins = 0;
  let websites = 0;
  for (const e of targets) {
    const now = deps.current(e.id) as T;
    const next = withDefaultMatch(now.item, domains, deps.baseDomain);
    if (!next) continue;
    deps.progress?.(logins, targets.length);
    try {
      await deps.update(now, next);
    } catch (err) {
      if (logins === 0) throw err;
      throw new MatchIncomplete(logins, err);
    }
    logins++;
    websites += changedCount(now.item, next);
  }
  return { logins, websites };
}
