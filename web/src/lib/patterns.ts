/**
 * Website entries that run as regular expressions, and what the item editor says under them. Pure: the core comes in
 * as an argument (the web vault passes its own; another app may pass its own). Unit-tested in `patterns.test.ts`.
 */
import type { UrlMatch } from "./types";

/** What the check needs of the core. */
export interface PatternCore {
  resolveMatch(url: string, match: string, defaultMatch: string): string;
  regexError(pattern: string): string | undefined;
  regexWarning(pattern: string): string | undefined;
}

/** A line under a website entry: why its pattern never matches (error), or that it could match other sites (warning). */
export interface PatternNote {
  kind: "error" | "warning";
  text: string;
}

/** Shown under a pattern the core says isn't tied to one website (`regexWarning`). Saving isn't blocked. */
export const PATTERN_WARNING = "This pattern isn't tied to one website, so it could match other sites. Start it with ^https://example\\.com/ (your site's address).";

/**
 * What to say under a website entry, `defaultMatch` being the app's own default for entries on "default". Only for an
 * entry that runs as a regular expression (`resolveMatch` says "regex": a "Regular expression" entry, or one on
 * "default" while the app's default is regex; never a plain address, which the core then matches by domain): the
 * core's reason it can't be used (`regexError`), else its warning that it could also match other websites
 * (`regexWarning`). Null otherwise, and for an empty entry.
 */
export function patternNote(core: PatternCore, url: string, match: UrlMatch, defaultMatch: string): PatternNote | null {
  if (typeof url !== "string" || !url.trim()) return null;
  try {
    if (core.resolveMatch(url, match, defaultMatch) !== "regex") return null;
    const error = core.regexError(url);
    if (error) return { kind: "error", text: `This pattern can't be used, so it never matches a page: ${error}` };
    return core.regexWarning(url) ? { kind: "warning", text: PATTERN_WARNING } : null;
  } catch {
    return null;
  }
}
