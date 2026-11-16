// Where a new passkey is saved: the core's rule (passkeySaveTargets / passkeyDefaultTarget), through src/background/site.ts.

import { expect, test } from "vitest";
import { NEW_LOGIN, type PasskeyLogin, passkeyDefaultTarget, passkeySaveTargets } from "../src/background/site";

let n = 0;
const own = (name: string, username: string, urls: string[], extra: Partial<PasskeyLogin> = {}): PasskeyLogin => ({
  id: `id-${++n}`,
  name,
  username,
  urls,
  writable: true,
  personal: true,
  ...extra,
});
/** In a vault somebody shared with the user, with write access: what an attacker can plant. */
const shared = (name: string, username: string, urls: string[], extra: Partial<PasskeyLogin> = {}) => own(name, username, urls, { personal: false, vault: "Family", ...extra });
const HOST = "login.example.com";
const RP = "example.com";
const targets = (logins: PasskeyLogin[], user = "alex@example.com", display = "Alex") => passkeySaveTargets(logins, HOST, RP, user, display);

test("websites: scheme optional, any letter case, a trailing dot; bad addresses never match", () => {
  const a = own("Example", "alex", ["https://Login.Example.com/path", "http://[bad", ""]);
  const b = own("Apex", "alex", ["example.com."]);
  expect(targets([a, b]).map((x) => [x.name, x.preferred])).toStrictEqual([
    ["Example", true],
    ["Apex", false],
  ]);
});

test("own login for this exact host is preselected", () => {
  const a = own("Example", "alex@example.com", ["https://login.example.com"]);
  const t = targets([a]);
  expect(t).toStrictEqual([{ id: a.id, name: "Example", username: "alex@example.com", preferred: true }]);
  expect(passkeyDefaultTarget(t)).toBe(a.id);
});

test("planted shared-vault login for the exact host: listed with its vault, never preselected", () => {
  const planted = shared("Example", "alex@example.com", ["https://login.example.com"]);
  const t = targets([planted]);
  expect(t).toStrictEqual([{ id: planted.id, name: "Example", username: "alex@example.com", preferred: false, vault: "Family" }]);
  // Nothing preferred: the window preselects "New login".
  expect(t.find((x) => x.preferred)).toBe(undefined);
  expect(passkeyDefaultTarget(t)).toBe(NEW_LOGIN);
});

test("own login wins over a shared one even when the shared one matches better", () => {
  const planted = shared("AAA first by name", "alex@example.com", ["https://login.example.com"]);
  const mine = own("Zed", "someone-else", ["https://login.example.com"]);
  const t = targets([planted, mine]);
  expect(t.map((x) => [x.id, x.preferred])).toStrictEqual([
    [mine.id, true],
    [planted.id, false],
  ]);
  expect(t.find((x) => x.preferred)!.id).toBe(mine.id);
});

test("own login only for the RP ID or a sibling subdomain: offered, not preselected (as before)", () => {
  const apex = own("Example", "alex", ["example.com"]);
  const sibling = own("Example app", "alex", ["https://app.example.com"]);
  const t = targets([sibling, apex]);
  expect(t.map((x) => x.preferred)).toStrictEqual([false, false]);
  expect(t.length).toBe(2);
});

test("order among own logins: exact host, then matching user name, then name", () => {
  const exact = own("B exact", "other", ["https://login.example.com"]);
  const user = own("A user", "alex@example.com", ["https://example.com"]);
  const neither = own("A neither", "other", ["https://example.com"]);
  const both = own("Z both", "alex", ["https://login.example.com"]);
  expect(targets([neither, user, exact, both]).map((x) => x.name)).toStrictEqual(["Z both", "B exact", "A user", "A neither"]);
});

test("read-only logins and other sites are never targets", () => {
  const ro = own("Read only", "alex", ["https://login.example.com"], { writable: false });
  const sharedRo = shared("Shared read only", "alex", ["https://login.example.com"], { writable: false });
  const other = own("Other", "alex", ["https://example.org"]);
  const lookalike = own("Lookalike", "alex", ["https://notexample.com"]);
  expect(targets([ro, sharedRo, other, lookalike])).toStrictEqual([]);
});

test("a shared vault without a name still shows as shared", () => {
  const s = shared("Example", "alex", ["https://login.example.com"], { vault: "" });
  expect(targets([s])[0]?.vault).toBe("Shared vault");
});
