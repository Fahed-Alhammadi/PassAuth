/**
 * Site logic, from the Rust core (crates/core/src/site through WASM): the one implementation every PassAuth app calls
 * — host names (UTS #46 IDNA, the full Public Suffix List), website matching for every match type, the https → http
 * downgrade rule, regular expressions (a linear-time engine; `regexError` says why a pattern is refused), the save
 * rule and passkey "Save in" targets. RP IDs are checked in passkeys.ts (`effectiveRpId`). The golden vectors
 * (testdata/vectors.json) pin the answers; test/vectors.test.ts checks these wrappers against them.
 *
 * These are thin wrappers keeping the shapes the worker's call sites use: a saved website as `LoginUrl`, the user's
 * "Default URI match detection" setting for `match: "default"`, `null` for "not offered". The extension's own rules
 * stay at the call sites: regular expressions count only for logins in the user's own vaults (`allowRegex`, see
 * matching.ts) and "default" follows the setting.
 *
 * The core must be loaded first (core.ts `initCore`; every entry point of the worker waits for it). Content scripts
 * have no core: the worker decides, and sends a document the exact origin it checked (fill.ts).
 */
import type { LoginUrl, UrlMatch } from "@web/lib/types";
import type { PasskeyLogin, PasskeyTarget, SaveCandidate, SavePlan, SaveTarget, SiteSavedUrl } from "../wasm/passauth_core";
import * as core from "../wasm/passauth_core";

export { NEW_LOGIN } from "../shared/save-text";
export type { PasskeyLogin, PasskeyTarget, SaveCandidate, SavePlan, SaveTarget };

/** The user's "Default URI match detection" setting: what a website saved with `match: "default"` follows. */
export type DefaultMatch = Exclude<UrlMatch, "default">;

/**
 * Only strings cross into the core where it takes text: its bindings don't check. Anything else (a number a page put
 * into a passkey request, say) doesn't read the wrong memory, but it isn't harmless either: a number traps inside the
 * core ("memory access out of bounds"), and an object with a large `length` makes the glue allocate that much memory,
 * which is never freed. Objects go through serde, which checks.
 */
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** `new URL(url)`, a missing scheme read as https, or null. Reading an address only: no site rule. */
export function parse(url: string): URL | null {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`);
  } catch {
    return null;
  }
}

/** What "domain" matching compares: the registrable domain ("example.co.uk", "home.duckdns.org"), else the host itself. */
export const baseDomain = (host: string): string => core.baseDomain(str(host));

/** The public suffix by the full list ("co.uk", "myfritz.net", "com"); "" for IP addresses and invalid hosts. */
export const publicSuffix = (host: string): string => core.publicSuffix(str(host));

/** The canonical host (IDNA to ASCII, lower case, IP addresses normalised, no trailing dot), or null for an invalid one. */
export const normalizeHost = (host: string): string | null => core.normalizeHost(str(host)) ?? null;

/** A saved website as the core takes it. Item data is whatever was typed or imported: a missing match type is "default". */
const urlOf = (saved: LoginUrl): string => str(saved?.url);
const matchOf = (saved: LoginUrl): string => (typeof saved?.match === "string" ? saved.match : "default");

/**
 * Does the page match a saved website? `fallback`: the user's default for `match: "default"`. `allowRegex`: false for
 * a login in a vault somebody shared (its regular expressions never count, not even through "default").
 */
export function matchesUrl(page: string, saved: LoginUrl, fallback: DefaultMatch = "domain", allowRegex = true): boolean {
  return core.matchesUrl(str(page), urlOf(saved), matchOf(saved), str(fallback), allowRegex === true);
}

/**
 * The entries of `list` with a website that matches `page`, in their order: every website of every entry against the
 * page in one call (the page is read once). `urlsOf`: an entry's websites; `allowRegex`: whether its regular
 * expressions count (only for the user's own logins).
 */
export function matchingEntries<T>(page: string, list: readonly T[], urlsOf: (entry: T) => readonly LoginUrl[], allowRegex: (entry: T) => boolean, fallback: DefaultMatch): T[] {
  const saved: SiteSavedUrl[] = [];
  const owner: number[] = [];
  list.forEach((entry, i) => {
    const regex = allowRegex(entry) === true;
    for (const u of urlsOf(entry)) {
      saved.push({ url: urlOf(u), match: matchOf(u), allowRegex: regex });
      owner.push(i);
    }
  });
  if (!saved.length) return [];
  const hits = new Set<number>();
  core.matchUrls(str(page), str(fallback), saved).forEach((hit, k) => {
    if (hit) hits.add(owner[k]!);
  });
  return list.filter((_, i) => hits.has(i));
}

/** True when filling would send a secret saved for an https site to an http page (localhost excepted). */
export const downgrade = (page: string, saved: LoginUrl): boolean => core.downgrade(str(page), urlOf(saved), matchOf(saved));

/** Why a regular-expression website is refused (never matches), or null when it is evaluated. */
export const regexError = (pattern: string): string | null => core.regexError(str(pattern)) ?? null;

/** The save rule (docs/ARCHITECTURE.md "Save rule"): what to offer for what was typed, given the logins for the page. */
export const planSave = (candidates: SaveCandidate[], typedUser: string, password: string): SavePlan => core.planSave(candidates, str(typedUser), str(password));

/**
 * The target the prompt answered with, if this save offered it ("new" or one of `plan.targets`), else null. What is
 * applied is what the prompt displayed, never a default worked out again later.
 */
export const chosenTarget = (plan: { targets: SaveTarget[] }, answer: unknown): string | null => core.chosenSaveTarget(plan, answer) ?? null;

/** A login after the submitted credentials were saved into it: the password always, the user name only when one was typed. */
export function applyToLogin<T extends { username: string; password: string }>(login: T, typedUser: string, password: string): T {
  return { ...login, username: typedUser.trim() || login.username, password };
}

/**
 * Logins a new passkey can be saved in, best first: ones the user can edit whose website is this exact host, the RP
 * ID or a subdomain of it, the user's own first. Only an own login for the exact host is `preferred` (preselected);
 * a login in a shared vault names its vault and is never preselected.
 */
export const passkeySaveTargets = (logins: PasskeyLogin[], host: string, rpId: string, userName: string, displayName: string): PasskeyTarget[] =>
  core.passkeySaveTargets(logins, str(host), str(rpId), str(userName), str(displayName));

/** The preselected "Save in" choice: the first preferred target's id, else `NEW_LOGIN`. */
export const passkeyDefaultTarget = (targets: PasskeyTarget[]): string => core.passkeyDefaultTarget(targets);
