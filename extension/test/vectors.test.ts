// The shared golden vectors (testdata/vectors.json, read only, generated from the Rust core by
// testdata/generate-vectors.mjs) against the extension's own wrappers around the core: site.ts (host names, matching
// with the user's default and the shared-vault regex rule, the save rule, passkey "Save in"), the match index the
// toolbar badge counts with, and passkeys.ts (RP IDs, as the page sees them). Every case must hold here, through the
// same calls the worker makes. A case marked for other clients only (`only` without "extension") is skipped;
// `known.extension`, if a case ever carries one, is the extension's own answer.

import type { LoginUrl, UrlMatch } from "@web/lib/types";
import { expect, test } from "vitest";
import { matchingIds } from "../src/background/match-index";
import { effectiveRpId, PasskeyError } from "../src/background/passkeys";
import {
  baseDomain,
  type DefaultMatch,
  downgrade,
  matchesUrl,
  matchingEntries,
  normalizeHost,
  type PasskeyLogin,
  passkeyDefaultTarget,
  passkeySaveTargets,
  planSave,
  publicSuffix,
  regexError,
  type SaveCandidate,
} from "../src/background/site";
import { publicSuffixListVersion } from "../src/wasm/passauth_core";

type Case = { only?: string[]; known?: Record<string, unknown> } & Record<string, unknown>;

interface Vectors {
  version: number;
  publicSuffixList: string;
  normalizeHost: (Case & { host: string; expected: string | null })[];
  baseDomain: (Case & { host: string; expected: string })[];
  publicSuffix: (Case & { host: string; expected: string })[];
  urlMatch: (Case & { page: string; url: string; match: string; defaultMatch: string; allowRegex: boolean; expected: boolean; note: string })[];
  downgrade: (Case & { page: string; url: string; match: string; expected: boolean; note: string })[];
  regexError: (Case & { pattern: string; expected: string | null })[];
  savePlan: (Case & { name: string; candidates: SaveCandidate[]; typedUser: string; password: string; expected: unknown })[];
  passkeyTargets: (Case & { name: string; logins: PasskeyLogin[]; host: string; rpId: string; userName: string; displayName: string; expected: unknown; expectedDefault: string })[];
  rpId: (Case & { origin: string; requested: string | null; expected: string | null; error?: string; message?: string; note: string })[];
}

const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const vectors = Object.values(files)[0] as Vectors | undefined;

/** Cases this client answers: all but those marked for other clients only. */
const mine = <T extends Case>(cases: T[]) => cases.filter((c) => !c.only || c.only.includes("extension"));
/** The extension's expected answer: its own `known` entry if a case has one, else the reference value. */
const expectedFor = (c: Case & { expected: unknown }) => (c.known && "extension" in c.known ? c.known.extension : c.expected);

/** A saved website as items carry it (the vectors also use match types no item has, to pin what the core does then). */
const saved = (url: string, match: string): LoginUrl => ({ url, match: match as UrlMatch });

test("testdata/vectors.json is there, has every section and comes from the core the extension bundles", () => {
  expect(vectors, "testdata/vectors.json (node testdata/generate-vectors.mjs)").toBeDefined();
  expect(vectors?.version).toBe(2);
  for (const section of ["normalizeHost", "baseDomain", "publicSuffix", "urlMatch", "downgrade", "regexError", "savePlan", "passkeyTargets", "rpId"] as const) {
    expect(vectors?.[section].length, section).toBeGreaterThan(0);
  }
  // The same Public Suffix List as src/wasm (scripts/build-wasm.sh extension/src/wasm after a core change).
  expect(publicSuffixListVersion()).toBe(vectors?.publicSuffixList);
});

const v = vectors as Vectors;

test("host names, base domains and public suffixes", () => {
  for (const c of mine(v.normalizeHost)) expect(normalizeHost(c.host), c.host).toBe(expectedFor(c));
  for (const c of mine(v.baseDomain)) expect(baseDomain(c.host), c.host).toBe(expectedFor(c));
  for (const c of mine(v.publicSuffix)) expect(publicSuffix(c.host), c.host).toBe(expectedFor(c));
});

test("website matching, one website at a time and in one call (incl. shared-vault logins, whose regular expressions never count)", () => {
  for (const c of mine(v.urlMatch)) {
    const label = `${c.note}: ${c.page} vs ${c.url} (${c.match}, default ${c.defaultMatch}, allowRegex ${c.allowRegex})`;
    const fallback = c.defaultMatch as DefaultMatch;
    expect(matchesUrl(c.page, saved(c.url, c.match), fallback, c.allowRegex), label).toBe(expectedFor(c));
    const one = [{ urls: [saved(c.url, c.match)], own: c.allowRegex }];
    expect(
      matchingEntries(
        c.page,
        one,
        (l) => l.urls,
        (l) => l.own,
        fallback,
      ).length === 1,
      label,
    ).toBe(expectedFor(c));
  }
});

test("the match index (toolbar badge, inline menu icon) counts by the same rule", () => {
  for (const c of mine(v.urlMatch)) {
    const index = { revision: 1, logins: [{ id: "l", urls: [saved(c.url, c.match)], personal: c.allowRegex }] };
    expect(matchingIds(index, c.page, c.defaultMatch as DefaultMatch).length === 1, c.note).toBe(expectedFor(c));
  }
});

test("the https → http downgrade rule and refused regular expressions", () => {
  for (const c of mine(v.downgrade)) expect(downgrade(c.page, saved(c.url, c.match)), c.note).toBe(expectedFor(c));
  for (const c of mine(v.regexError)) expect(regexError(c.pattern), c.pattern.slice(0, 40)).toBe(expectedFor(c));
});

test("the save rule", () => {
  for (const c of mine(v.savePlan)) {
    const p = planSave(c.candidates, c.typedUser, c.password);
    const targets = p.action === "none" ? [] : p.targets.map((t) => (t.vault ? { id: t.id, vault: t.vault } : { id: t.id }));
    const simple = p.action === "none" ? { action: "none" } : p.action === "create" ? { action: "create", targets } : { action: "update", reason: p.reason, target: p.target, targets };
    expect(simple, c.name).toStrictEqual(expectedFor(c));
  }
});

test('passkey "Save in" targets and the preselected one', () => {
  for (const c of mine(v.passkeyTargets)) {
    const t = passkeySaveTargets(c.logins, c.host, c.rpId, c.userName, c.displayName);
    expect(
      t.map((x) => ({ id: x.id, preferred: x.preferred, ...(x.vault ? { vault: x.vault } : {}) })),
      c.name,
    ).toStrictEqual(expectedFor(c));
    expect(passkeyDefaultTarget(t), c.name).toBe(c.expectedDefault);
  }
});

test("RP IDs: accepted ones, and the errors a page sees for the others", () => {
  for (const c of mine(v.rpId)) {
    const label = `${c.note}: ${c.origin} / ${c.requested}`;
    if (c.expected !== null) {
      expect(effectiveRpId(c.requested ?? undefined, c.origin), label).toBe(expectedFor(c));
      continue;
    }
    let error: unknown;
    try {
      effectiveRpId(c.requested ?? undefined, c.origin);
    } catch (e) {
      error = e;
    }
    expect(error, label).toBeInstanceOf(PasskeyError);
    expect([(error as Error).name, (error as Error).message], label).toStrictEqual([c.error, c.message]);
  }
});
