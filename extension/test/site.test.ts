// The worker's site logic (src/background/site.ts): thin wrappers over the core's (crates/core/src/site, the real
// WASM here), with the extension's own rules on top — the user's default match and regular expressions only for the
// user's own logins. The golden vectors (vectors.test.ts) pin every case; these are the ones PassAuth relies on most.
// And save-prompt password selection (src/content/pick.ts).

import type { LoginUrl } from "@web/lib/types";
import { expect, test } from "vitest";
import { baseDomain, downgrade, matchesUrl, matchingEntries, normalizeHost, parse, publicSuffix, regexError } from "../src/background/site";
import { submittedPassword } from "../src/content/pick";

// ------------------------------------------------------------------ host names and public suffixes

test("baseDomain: ordinary and regional suffixes, by the full Public Suffix List", () => {
  expect(baseDomain("www.example.com")).toBe("example.com");
  expect(baseDomain("login.example.co.uk")).toBe("example.co.uk");
  expect(baseDomain("a.b.example.com.sa")).toBe("example.com.sa");
  expect(baseDomain("EXAMPLE.COM.")).toBe("example.com");
  expect(baseDomain("localhost")).toBe("localhost");
  expect(baseDomain("192.168.1.10")).toBe("192.168.1.10");
  expect(publicSuffix("nas.myfritz.net")).toBe("myfritz.net");
  expect(normalizeHost("BÜCHER.de")).toBe("xn--bcher-kva.de");
  expect(normalizeHost("a b.com")).toBe(null);
});

test("baseDomain: dynamic DNS and hosting tenants are separate sites", () => {
  expect(baseDomain("home.duckdns.org")).toBe("home.duckdns.org");
  expect(baseDomain("nas.home.duckdns.org")).toBe("home.duckdns.org");
  expect(baseDomain("evil.duckdns.org")).not.toBe(baseDomain("home.duckdns.org"));
  // Private suffixes the old built-in list didn't have.
  expect(baseDomain("nas.x.myfritz.net")).toBe("x.myfritz.net");
  expect(baseDomain("box.myds.me")).toBe("box.myds.me");
  expect(baseDomain("app.cloudapp.net")).toBe("app.cloudapp.net");
  // A bare suffix stays as it is.
  expect(baseDomain("duckdns.org")).toBe("duckdns.org");
});

test("only text reaches the core: anything else counts as an empty host", () => {
  expect(baseDomain(42 as unknown as string)).toBe("");
  expect(matchesUrl(7 as unknown as string, { url: 8, match: 9 } as unknown as LoginUrl)).toBe(false);
  // The core still works afterwards.
  expect(baseDomain("www.example.com")).toBe("example.com");
});

// ------------------------------------------------------------------ matching

test("matchesUrl: domain matching never crosses tenants", () => {
  const item: LoginUrl = { url: "https://home.duckdns.org", match: "default" };
  expect(matchesUrl("https://home.duckdns.org/login", item, "domain")).toBe(true);
  expect(matchesUrl("https://nas.home.duckdns.org/", item, "domain")).toBe(true);
  expect(matchesUrl("https://evil.duckdns.org/login", item, "domain")).toBe(false);
  expect(matchesUrl("https://user.github.io/", { url: "https://other.github.io", match: "domain" })).toBe(false);
  expect(matchesUrl("https://accounts.example.com/", { url: "https://www.example.com", match: "domain" })).toBe(true);
  expect(matchesUrl("https://accounts.example.com/", { url: "https://www.example.com", match: "host" })).toBe(false);
  expect(matchesUrl("ftp://example.com/", { url: "https://example.com", match: "domain" })).toBe(false);
  // "default" follows the user's setting.
  expect(matchesUrl("https://accounts.example.com/", { url: "https://www.example.com", match: "default" }, "host")).toBe(false);
});

test("regex: query and fragment can't satisfy a pattern", () => {
  const item: LoginUrl = { url: "bank\\.com", match: "regex" };
  expect(matchesUrl("https://bank.com/login", item)).toBe(true);
  expect(matchesUrl("https://evil.com/?next=bank.com", item)).toBe(false);
  expect(matchesUrl("https://evil.com/#bank.com", item)).toBe(false);
});

test("regex: a linear-time engine (no pattern can stall a page), and regexError says why one is refused", () => {
  const started = performance.now();
  expect(matchesUrl(`https://example.com/${"a".repeat(3000)}`, { url: "(a+)+b", match: "regex" })).toBe(false);
  expect(matchesUrl(`https://example.com/${"a".repeat(3000)}`, { url: "(.|.)*Q", match: "regex" })).toBe(false);
  expect(performance.now() - started).toBeLessThan(500);
  expect(regexError("(a+)+")).toBe(null);
  expect(regexError("^https://(www\\.)?example\\.com/")).toBe(null);
  expect(regexError("(?<=a)b+")).toBe("Look-around is not supported.");
  expect(regexError("(a)\\1")).toBe("Backreferences are not supported.");
  expect(regexError("x".repeat(301))).toMatch(/longer than 300/);
  // A refused pattern never matches.
  expect(matchesUrl("https://bank.com/", { url: "(?=b)bank", match: "regex" })).toBe(false);
});

test("S13: regular expressions match only for the user's own items", () => {
  const item: LoginUrl = { url: "^https://bank\\.com/", match: "regex" };
  expect(matchesUrl("https://bank.com/login", item, "domain", true)).toBe(true);
  expect(matchesUrl("https://bank.com/login", item, "domain", false)).toBe(false);
  // "Default" with the user's default set to regex: the same rule.
  const byDefault: LoginUrl = { url: "^https://bank\\.com/", match: "default" };
  expect(matchesUrl("https://bank.com/login", byDefault, "regex", true)).toBe(true);
  expect(matchesUrl("https://bank.com/login", byDefault, "regex", false)).toBe(false);
  // Other rules don't care.
  expect(matchesUrl("https://bank.com/login", { url: "https://bank.com", match: "domain" }, "domain", false)).toBe(true);
});

test("matchingEntries: every website of every login in one call, in the logins' order, regex per login", () => {
  const logins = [
    { id: "own-regex", urls: [{ url: "^https://bank\\.com/", match: "regex" }] as LoginUrl[], own: true },
    { id: "shared-regex", urls: [{ url: "^https://bank\\.com/", match: "regex" }] as LoginUrl[], own: false },
    { id: "none", urls: [] as LoginUrl[], own: true },
    {
      id: "second-site",
      urls: [
        { url: "https://other.test", match: "domain" },
        { url: "https://www.bank.com", match: "default" },
      ] as LoginUrl[],
      own: false,
    },
    // Imported data that isn't a website: never a match, and it doesn't break the others.
    { id: "broken", urls: [{ url: null, match: undefined }] as unknown as LoginUrl[], own: true },
  ];
  const ids = (page: string, fallback: "domain" | "host" = "domain") =>
    matchingEntries(
      page,
      logins,
      (l) => l.urls,
      (l) => l.own,
      fallback,
    ).map((l) => l.id);
  expect(ids("https://bank.com/login")).toStrictEqual(["own-regex", "second-site"]);
  expect(ids("https://bank.com/login", "host")).toStrictEqual(["own-regex"]);
  expect(ids("https://nothing.test/")).toStrictEqual([]);
  expect(
    matchingEntries(
      "https://bank.com/",
      [],
      () => [],
      () => true,
      "domain",
    ),
  ).toStrictEqual([]);
});

test("downgrade: https logins are not sent to http pages", () => {
  expect(downgrade("http://example.com/", { url: "https://example.com", match: "domain" })).toBe(true);
  expect(downgrade("https://example.com/", { url: "https://example.com", match: "domain" })).toBe(false);
  expect(downgrade("http://localhost:8080/", { url: "https://localhost", match: "domain" })).toBe(false);
});

test("parse: a missing scheme reads as https; nonsense is null", () => {
  expect(parse("example.com/login")?.href).toBe("https://example.com/login");
  expect(parse("http://[::1")).toBe(null);
});

// ------------------------------------------------------------------ save prompt

const f = (value: string, autocomplete = "") => ({ value, autocomplete });

test("submittedPassword: sign-in form", () => {
  expect(submittedPassword([f("hunter2")])).toBe("hunter2");
  expect(submittedPassword([f("")])).toBe("");
  expect(submittedPassword([])).toBe("");
});

test("submittedPassword: change-password forms save the new password", () => {
  // current + new + confirm
  expect(submittedPassword([f("old"), f("new1"), f("new1")])).toBe("new1");
  // marked with autocomplete
  expect(submittedPassword([f("old", "current-password"), f("new1", "new-password"), f("new1", "new-password")])).toBe("new1");
  // current + new (no confirm)
  expect(submittedPassword([f("old", "current-password"), f("new1")])).toBe("new1");
  // sign-up: new + confirm
  expect(submittedPassword([f("pw", "new-password"), f("pw")])).toBe("pw");
  // the empty current field is ignored
  expect(submittedPassword([f(""), f("new1", "new-password")])).toBe("new1");
});
