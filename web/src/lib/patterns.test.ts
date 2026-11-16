import { describe, expect, it } from "vitest";
import { PATTERN_WARNING, patternNote, type PatternCore } from "./patterns";

/** A core that resolves like the real one for these cases and refuses or warns about the patterns it is told to. */
function fakeCore(refused: Record<string, string> = {}, loose: string[] = []): PatternCore & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    resolveMatch(url, match, defaultMatch) {
      asked.push(`${match}/${defaultMatch}`);
      const plain = /^https?:\/\/[^\s^$*+?()[\]{}|\\]+$/.test(url);
      if (match === "regex") return "regex";
      if (match === "default") return defaultMatch === "regex" && !plain ? "regex" : defaultMatch === "regex" ? "domain" : defaultMatch;
      return match === "starts_with" ? "startsWith" : match;
    },
    regexError: (p) => refused[p],
    regexWarning: (p) => (loose.includes(p) ? "not anchored" : undefined),
  };
}

describe("website patterns in the item editor", () => {
  it("warns about a regular expression that isn't tied to one website", () => {
    const core = fakeCore({}, ["bank\\.com"]);
    expect(patternNote(core, "bank\\.com", "regex", "domain")).toEqual({ kind: "warning", text: PATTERN_WARNING });
    expect(PATTERN_WARNING).toContain("^https://example\\.com/");
    expect(patternNote(core, "^https://bank\\.com/", "regex", "domain")).toBeNull();
  });

  it("says why a pattern the core refuses never matches", () => {
    const core = fakeCore({ "(?=x)": "look-around isn't supported" });
    expect(patternNote(core, "(?=x)", "regex", "domain")).toEqual({ kind: "error", text: "This pattern can't be used, so it never matches a page: look-around isn't supported" });
  });

  it("checks entries on Default only when the app's default is regex, and never a plain address", () => {
    const core = fakeCore({}, ["bank\\.com", "https://bank.com"]);
    expect(patternNote(core, "bank\\.com", "default", "domain")).toBeNull();
    expect(patternNote(core, "bank\\.com", "default", "regex")?.kind).toBe("warning");
    expect(patternNote(core, "https://bank.com", "default", "regex")).toBeNull();
    for (const m of ["domain", "host", "starts_with", "exact", "never"] as const) expect(patternNote(core, "bank\\.com", m, "regex")).toBeNull();
  });

  it("says nothing for an empty entry, or when the core can't be asked", () => {
    expect(patternNote(fakeCore(), "  ", "regex", "domain")).toBeNull();
    const broken: PatternCore = {
      resolveMatch: () => {
        throw new Error("expected a string");
      },
      regexError: () => undefined,
      regexWarning: () => undefined,
    };
    expect(patternNote(broken, "x", "regex", "domain")).toBeNull();
  });
});
