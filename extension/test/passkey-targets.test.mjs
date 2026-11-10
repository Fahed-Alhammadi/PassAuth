// Tests for where a new passkey is saved (src/background/passkey-targets.ts).
// Run with plain Node (type stripping):  node extension/test/passkey-targets.test.mjs

import assert from "node:assert/strict";
import { hostsOf, passkeySaveTargets } from "../src/background/passkey-targets.ts";

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

let n = 0;
const own = (name, username, urls, extra = {}) => ({ id: `id-${++n}`, name, username, urls, writable: true, personal: true, ...extra });
/** In a vault somebody shared with the user, with write access: what an attacker can plant. */
const shared = (name, username, urls, extra = {}) => own(name, username, urls, { personal: false, vault: "Family", ...extra });
const HOST = "login.example.com";
const RP = "example.com";
const targets = (logins, user = "alex@example.com", display = "Alex") => passkeySaveTargets(logins, HOST, RP, user, display);

test("hostsOf: scheme optional, lowercase, no trailing dot, bad addresses skipped", () => {
  assert.deepEqual(hostsOf(["https://Login.Example.com/path", "example.com.", "http://[bad", ""]), ["login.example.com", "example.com"]);
});

test("own login for this exact host is preselected", () => {
  const a = own("Example", "alex@example.com", ["https://login.example.com"]);
  assert.deepEqual(targets([a]), [{ id: a.id, name: "Example", username: "alex@example.com", preferred: true }]);
});

test("planted shared-vault login for the exact host: listed with its vault, never preselected", () => {
  const planted = shared("Example", "alex@example.com", ["https://login.example.com"]);
  const t = targets([planted]);
  assert.deepEqual(t, [{ id: planted.id, name: "Example", username: "alex@example.com", preferred: false, vault: "Family" }]);
  // Nothing preferred: the window preselects "New login".
  assert.equal(t.find((x) => x.preferred), undefined);
});

test("own login wins over a shared one even when the shared one matches better", () => {
  const planted = shared("AAA first by name", "alex@example.com", ["https://login.example.com"]);
  const mine = own("Zed", "someone-else", ["https://login.example.com"]);
  const t = targets([planted, mine]);
  assert.deepEqual(t.map((x) => [x.id, x.preferred]), [[mine.id, true], [planted.id, false]]);
  assert.equal(t.find((x) => x.preferred).id, mine.id);
});

test("own login only for the RP ID or a sibling subdomain: offered, not preselected (as before)", () => {
  const apex = own("Example", "alex", ["example.com"]);
  const sibling = own("Example app", "alex", ["https://app.example.com"]);
  const t = targets([sibling, apex]);
  assert.deepEqual(t.map((x) => x.preferred), [false, false]);
  assert.equal(t.length, 2);
});

test("order among own logins: exact host, then matching user name, then name", () => {
  const exact = own("B exact", "other", ["https://login.example.com"]);
  const user = own("A user", "alex@example.com", ["https://example.com"]);
  const neither = own("A neither", "other", ["https://example.com"]);
  const both = own("Z both", "alex", ["https://login.example.com"]);
  assert.deepEqual(targets([neither, user, exact, both]).map((x) => x.name), ["Z both", "B exact", "A user", "A neither"]);
});

test("read-only logins and other sites are never targets", () => {
  const ro = own("Read only", "alex", ["https://login.example.com"], { writable: false });
  const sharedRo = shared("Shared read only", "alex", ["https://login.example.com"], { writable: false });
  const other = own("Other", "alex", ["https://example.org"]);
  const lookalike = own("Lookalike", "alex", ["https://notexample.com"]);
  assert.deepEqual(targets([ro, sharedRo, other, lookalike]), []);
});

test("a shared vault without a name still shows as shared", () => {
  const s = shared("Example", "alex", ["https://login.example.com"], { vault: "" });
  assert.equal(targets([s])[0].vault, "Shared vault");
});

// ------------------------------------------------------------------ runner

let failed = 0;
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL - ${name}\n${e?.stack ?? e}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exitCode = failed ? 1 : 0;
