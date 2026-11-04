// Tests for site matching (src/background/urls.ts, psl.ts) and save-prompt password selection (src/content/pick.ts).
// Run with plain Node (type stripping):  node extension/test/urls.test.mjs

import assert from "node:assert/strict";
import { baseDomain, downgrade, matchesUrl, unsafeRegex } from "../src/background/urls.ts";
import { submittedPassword } from "../src/content/pick.ts";

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// ------------------------------------------------------------------ baseDomain / public suffixes

test("baseDomain: ordinary and regional suffixes", () => {
  assert.equal(baseDomain("www.example.com"), "example.com");
  assert.equal(baseDomain("login.example.co.uk"), "example.co.uk");
  assert.equal(baseDomain("a.b.example.com.sa"), "example.com.sa");
  assert.equal(baseDomain("EXAMPLE.COM."), "example.com");
  assert.equal(baseDomain("localhost"), "localhost");
  assert.equal(baseDomain("192.168.1.10"), "192.168.1.10");
});

test("baseDomain: dynamic DNS and hosting tenants are separate sites", () => {
  assert.equal(baseDomain("home.duckdns.org"), "home.duckdns.org");
  assert.equal(baseDomain("nas.home.duckdns.org"), "home.duckdns.org");
  assert.notEqual(baseDomain("evil.duckdns.org"), baseDomain("home.duckdns.org"));
  assert.equal(baseDomain("me.ddns.net"), "me.ddns.net");
  assert.equal(baseDomain("box.synology.me"), "box.synology.me");
  assert.equal(baseDomain("app.fly.dev"), "app.fly.dev");
  assert.equal(baseDomain("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
  assert.equal(baseDomain("svc.up.railway.app"), "svc.up.railway.app");
  // A bare suffix stays as it is.
  assert.equal(baseDomain("duckdns.org"), "duckdns.org");
});

test("matchesUrl: domain matching never crosses tenants", () => {
  const item = { url: "https://home.duckdns.org", match: "default" };
  assert.equal(matchesUrl("https://home.duckdns.org/login", item, "domain"), true);
  assert.equal(matchesUrl("https://nas.home.duckdns.org/", item, "domain"), true);
  assert.equal(matchesUrl("https://evil.duckdns.org/login", item, "domain"), false);
  assert.equal(matchesUrl("https://user.github.io/", { url: "https://other.github.io", match: "domain" }), false);
  assert.equal(matchesUrl("https://accounts.example.com/", { url: "https://www.example.com", match: "domain" }), true);
  assert.equal(matchesUrl("https://accounts.example.com/", { url: "https://www.example.com", match: "host" }), false);
  assert.equal(matchesUrl("ftp://example.com/", { url: "https://example.com", match: "domain" }), false);
});

// ------------------------------------------------------------------ regex guard

test("regex: query and fragment can't satisfy a pattern", () => {
  const item = { url: "bank\\.com", match: "regex" };
  assert.equal(matchesUrl("https://bank.com/login", item), true);
  assert.equal(matchesUrl("https://evil.com/?next=bank.com", item), false);
  assert.equal(matchesUrl("https://evil.com/#bank.com", item), false);
});

test("regex: unsafe or oversized patterns are not evaluated", () => {
  assert.equal(unsafeRegex("(a+)+$"), true);
  assert.equal(unsafeRegex("(.*a){10}"), true);
  assert.equal(unsafeRegex("x".repeat(301)), true);
  assert.equal(unsafeRegex("^https://(www\\.)?example\\.com/"), false);
  assert.equal(matchesUrl("https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com/", { url: "(a+)+b", match: "regex" }), false);
  assert.equal(matchesUrl("https://example.com/", { url: "(unclosed", match: "regex" }), false);
});

test("downgrade: https logins are not sent to http pages", () => {
  assert.equal(downgrade("http://example.com/", { url: "https://example.com", match: "domain" }), true);
  assert.equal(downgrade("https://example.com/", { url: "https://example.com", match: "domain" }), false);
  assert.equal(downgrade("http://localhost:8080/", { url: "https://localhost", match: "domain" }), false);
});

// ------------------------------------------------------------------ save prompt

const f = (value, autocomplete = "") => ({ value, autocomplete });

test("submittedPassword: sign-in form", () => {
  assert.equal(submittedPassword([f("hunter2")]), "hunter2");
  assert.equal(submittedPassword([f("")]), "");
  assert.equal(submittedPassword([]), "");
});

test("submittedPassword: change-password forms save the new password", () => {
  // current + new + confirm
  assert.equal(submittedPassword([f("old"), f("new1"), f("new1")]), "new1");
  // marked with autocomplete
  assert.equal(submittedPassword([f("old", "current-password"), f("new1", "new-password"), f("new1", "new-password")]), "new1");
  // current + new (no confirm)
  assert.equal(submittedPassword([f("old", "current-password"), f("new1")]), "new1");
  // sign-up: new + confirm
  assert.equal(submittedPassword([f("pw", "new-password"), f("pw")]), "pw");
  // the empty current field is ignored
  assert.equal(submittedPassword([f(""), f("new1", "new-password")]), "new1");
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
