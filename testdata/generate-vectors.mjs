// Golden vectors for the site logic every PassAuth client uses: host names, public suffixes and
// base domains (the full Public Suffix List), website matching (`allowRegex`: false for a login in
// a vault somebody shared, whose regular expressions never count), the https→http downgrade rule,
// the regular-expression engine's refusals and warnings, the save rule, passkey "Save in" targets
// and RP ID checks. Also the phrases an approving app offers for a sign-in request
// (`loginPhraseChoices`), which must be the same on every device and in every binding.
//
// The expected values come from the Rust core (crates/core/src/site) through its WASM build: the
// one implementation every client calls (the web vault and the extension through WASM, the iOS,
// macOS AutoFill and Android apps through UniFFI). The vectors pin its answers, so a change to the
// logic or to the suffix list shows up as a diff here, and each client's tests check that its
// bindings and its own wrappers (call sites, the user's default match, the shared-vault regex rule)
// give the same answers.
//
//   node testdata/generate-vectors.mjs                 builds the core for WASM into a temporary
//                                                      folder (scripts/build-wasm.sh) and writes
//                                                      testdata/vectors.json
//   node testdata/generate-vectors.mjs --check         the same, but fails when vectors.json is out
//                                                      of date instead of writing it
//   node testdata/generate-vectors.mjs --wasm <dir>    uses an existing build instead
//                                                      (scripts/build-wasm.sh <dir>, e.g.
//                                                      extension/src/wasm) of the current core
//
// Every run also checks the WASM build itself (it doesn't change vectors.json): every string
// parameter of every export, as its passauth_core.d.ts declares them, must refuse a number, boolean,
// object or array with a clean Error("expected a string"), without a trap and without growing WASM
// memory (review L1: wasm-bindgen's own string passing trusted the type and could trap or allocate
// gigabytes). A new export is covered without listing it here; a new class needs a fixture in
// `instances`.
//
// Building needs what scripts/build-wasm.sh needs: Rust with the wasm32-unknown-unknown target and
// the wasm-bindgen CLI in the version of Cargo.lock. Consumers: crates/core/tests/vectors.rs,
// extension/test/vectors.test.ts, ios/Tests/GoldenVectorTests.swift (iOS and the macOS AutoFill
// tests) and android/app/src/test/kotlin/io/passauth/app/GoldenVectorsTest.kt.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(here, "vectors.json");

const args = process.argv.slice(2);
const check = args.includes("--check");
const at = args.indexOf("--wasm");
if (at >= 0 && !args[at + 1]) {
  console.error("usage: node testdata/generate-vectors.mjs [--check] [--wasm <dir built by scripts/build-wasm.sh>]");
  process.exit(2);
}
const temp = at >= 0 ? null : mkdtempSync(join(tmpdir(), "passauth-vectors-"));
const wasmDir = temp ?? resolve(args[at + 1]);

let text;
try {
  if (temp) {
    // The build's own output goes to stderr, so `--check` prints only its verdict.
    execFileSync(join(root, "scripts", "build-wasm.sh"), [temp], { cwd: root, stdio: ["ignore", 2, 2] });
  }
  const core = await import(pathToFileURL(join(wasmDir, "passauth_core.js")).href);
  const { memory } = core.initSync({ module: readFileSync(join(wasmDir, "passauth_core_bg.wasm")) });
  checkStringArguments(core, memory, readFileSync(join(wasmDir, "passauth_core.d.ts"), "utf8"));
  text = JSON.stringify(vectors(core), null, 2) + "\n";
} finally {
  if (temp) rmSync(temp, { recursive: true, force: true });
}

if (check) {
  const now = readFileSync(out, "utf8");
  if (now !== text) {
    console.error("testdata/vectors.json is out of date: run node testdata/generate-vectors.mjs");
    process.exit(1);
  }
  console.log("testdata/vectors.json is up to date");
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}

function vectors(core) {
  // ------------------------------------------------------------ (a) host names and sites

  const normalizeHostInputs = [
    "www.example.com", "EXAMPLE.COM.", "BÜCHER.de", "straße.de", "xn--bcher-kva.de", "ａｂｃ.com", "exa%41mple.com",
    "0x7f.1", "1.2.3", "192.168.1.10", "[::1]", "[2001:DB8:0:0:0:0:0:1]", "[::ffff:1.2.3.4]", "a..b", "example.com..",
    "::1", "a b.com", "192.168.1.256", "xn--abc", "", ".",
  ];
  const normalizeHostCases = normalizeHostInputs.map((host) => ({ host, expected: core.normalizeHost(host) ?? null }));

  const hosts = [
    "www.example.com", "example.com", "EXAMPLE.COM.", "a.b.c", "foo.bar.baz.qux.example.org",
    "login.example.co.uk", "example.co.uk", "co.uk", "a.b.example.com.sa", "shop.example.com.au",
    "home.duckdns.org", "nas.home.duckdns.org", "duckdns.org", "evil.duckdns.org",
    "bucket.s3.amazonaws.com", "x.bucket.s3.amazonaws.com", "svc.up.railway.app", "a.b.svc.up.railway.app", "up.railway.app",
    "user.github.io", "a.user.github.io", "github.io", "my.box.synology.me", "app.fly.dev",
    // Dynamic DNS and cloud names from the list's private section: sites of their own.
    "nas.myfritz.net", "x.nas.myfritz.net", "myfritz.net", "home.myds.me", "myds.me", "a.dedyn.io", "dedyn.io",
    "app.cloudapp.net", "cloudapp.net", "ec2-1-2-3-4.us-east-2.compute.amazonaws.com", "us-east-2.compute.amazonaws.com",
    "x.eu-west-1.compute.amazonaws.com",
    // Wildcard and exception rules, an unknown top-level domain (implicit "*" rule).
    "x.foo.ck", "www.ck", "a.b.internal",
    "localhost", "app.localhost", "192.168.1.10", "10.0.0.1", "[::1]", "::1", "[2001:db8::1]",
    "xn--bcher-kva.de", "shop.xn--bcher-kva.de", "BÜCHER.de", "pvt.k12.ma.us", "example.com..", "",
  ];
  const baseDomainCases = hosts.map((host) => ({ host, expected: core.baseDomain(host) }));
  const publicSuffixCases = hosts.map((host) => ({ host, expected: core.publicSuffix(host) }));

  // ------------------------------------------------------------ (b) website matching

  /** [page, saved url, match, defaultMatch (resolves "default"), note] */
  const matchInputs = [
    // domain (registrable domain by the full Public Suffix List; ports and scheme ignored)
    ["https://www.example.com/login", "https://example.com", "domain", "domain", "subdomain of the saved site"],
    ["https://login.example.co.uk/", "https://www.example.co.uk/", "domain", "domain", "multi-label suffix"],
    ["https://evil.duckdns.org/", "https://home.duckdns.org/", "domain", "domain", "dynamic DNS names are separate sites"],
    ["https://nas.home.duckdns.org/", "https://home.duckdns.org", "domain", "domain", "below a dynamic DNS name"],
    ["https://attacker.myfritz.net/", "https://nas.myfritz.net", "domain", "domain", "names under myfritz.net are separate sites"],
    ["https://x.nas.myfritz.net/", "https://nas.myfritz.net", "domain", "domain", "below a myfritz.net name"],
    ["https://evil.myds.me/", "https://home.myds.me", "domain", "domain", "names under myds.me are separate sites"],
    ["https://b.dedyn.io/", "https://a.dedyn.io", "domain", "domain", "names under dedyn.io are separate sites"],
    ["https://b.cloudapp.net/", "https://a.cloudapp.net", "domain", "domain", "names under cloudapp.net are separate sites"],
    ["https://ec2-5-6-7-8.us-east-2.compute.amazonaws.com/", "https://ec2-1-2-3-4.us-east-2.compute.amazonaws.com", "domain", "domain", "EC2 hosts are separate sites (wildcard rule)"],
    ["https://a.b.internal/", "https://c.b.internal", "domain", "domain", "unknown top-level domain (implicit * rule)"],
    ["https://example.com:8443/x", "https://example.com", "domain", "domain", "port ignored"],
    ["https://example.org/", "https://example.com/", "domain", "domain", "other site"],
    ["http://example.com/", "https://example.com/", "domain", "domain", "scheme ignored by the match itself (see downgrade)"],
    ["https://192.168.1.10:8443/", "https://192.168.1.10", "domain", "domain", "IP address is its own site"],
    ["https://192.168.1.11/", "https://192.168.1.10", "domain", "domain", "other IP address"],
    ["https://example.com/", "example.com", "domain", "domain", "saved without a scheme = https"],
    ["https://EXAMPLE.com./", "https://example.com", "domain", "domain", "trailing dot and case"],
    ["ftp://example.com/", "https://example.com", "domain", "domain", "page not http(s)"],
    ["https://xn--bcher-kva.de/login", "https://bücher.de", "domain", "domain", "punycode page, Unicode saved"],
    ["https://bücher.de/", "https://xn--bcher-kva.de", "domain", "domain", "Unicode page, punycode saved"],
    ["https://BÜCHER.de/", "https://bücher.de/", "host", "domain", "Unicode host compared after IDNA mapping"],
    ["https://xn--strae-oqa.de/", "https://straße.de", "host", "domain", "UTS #46 keeps ß (no mapping to ss)"],
    ["https://strasse.de/", "https://straße.de", "host", "domain", "ss is another name"],
    ["https://[::1]:8080/", "http://[::1]:8080", "domain", "domain", "IPv6"],
    ["http://localhost:3000/", "http://localhost:3000/", "domain", "domain", "localhost"],
    ["https://example.co.uk/", "https://other.co.uk/", "domain", "domain", "different names under a multi-label suffix"],
    // app addresses (androidapp://…) are not websites
    ["https://example.app/", "androidapp://com.example.app", "domain", "domain", "an app login never matches a website"],
    ["https://com.example.app/", "androidapp://com.example.app", "host", "domain", "not even a host with the same labels"],
    ["https://example.com/", "androidapp://example.com", "domain", "domain", "nor the website of the same name"],
    ["https://example.com/", "androidapp://example.com", "default", "domain", "app address, default → domain"],
    ["https://example.com/", "androidapp://example.com", "starts_with", "domain", "app address, starts with"],
    ["https://example.com/", "androidapp://example.com", "exact", "domain", "app address, exact"],
    // default: resolved with the user's setting
    ["https://login.example.com/", "https://www.example.com", "default", "domain", "default → domain"],
    ["https://login.example.com/", "https://www.example.com", "default", "host", "default → host"],
    ["https://www.example.com/", "https://www.example.com", "default", "host", "default → host"],
    ["https://www.example.com/", "https://www.example.com", "default", "never", "default → never"],
    ["https://example.com/login", "https://example.com/login", "default", "exact", "default → exact"],
    ["https://example.com/login?x=1", "https://example.com/login", "default", "starts_with", "default → starts with"],
    ["https://login.example.com/", "https://www.example.com", "default", "default", "a default of default → domain"],
    ["https://login.example.com/", "https://www.example.com", "default", "bogus", "an unknown default → domain"],
    ["https://www.example.com/", "https://www.example.com", "bogus", "domain", "an unknown match type never matches"],
    // host (host name and port)
    ["https://www.example.com/x", "https://www.example.com", "host", "domain", "same host"],
    ["https://login.example.com/", "https://www.example.com", "host", "domain", "other host, same site"],
    ["https://example.com:8443/", "https://example.com:8443/login", "host", "domain", "same port"],
    ["https://example.com:8443/", "https://example.com", "host", "domain", "other port"],
    ["https://example.com:443/", "https://example.com", "host", "domain", "default port dropped"],
    ["http://example.com:80/", "http://example.com", "host", "domain", "default http port dropped"],
    ["https://example.com./", "https://example.com", "host", "domain", "trailing dot is part of the host"],
    ["http://example.com/", "https://example.com", "host", "domain", "scheme ignored"],
    // starts with (normalised href)
    ["https://example.com/login/step2", "https://example.com/login", "starts_with", "domain", "below the saved path"],
    ["https://example.com/logout", "https://example.com/login", "starts_with", "domain", "other path"],
    ["https://example.com/", "https://example.com", "starts_with", "domain", "empty path = /"],
    ["https://example.com.evil.com/", "https://example.com", "starts_with", "domain", "host prefix is not enough"],
    ["https://EXAMPLE.com/Login", "https://example.com/login", "starts_with", "domain", "paths are case-sensitive"],
    ["http://example.com/login", "https://example.com/login", "starts_with", "domain", "scheme differs"],
    ["https://example.com:443/login?next=1", "https://example.com/login", "starts_with", "domain", "default port and query"],
    // exact (normalised href, incl. query and fragment)
    ["https://example.com/login", "https://example.com/login", "exact", "domain", "same address"],
    ["https://example.com/login?x=1", "https://example.com/login", "exact", "domain", "query differs"],
    ["https://example.com", "https://example.com/", "exact", "domain", "empty path = /"],
    ["https://Example.COM/login", "https://example.com/login", "exact", "domain", "host case"],
    ["https://example.com:443/login", "https://example.com/login", "exact", "domain", "default port"],
    ["https://example.com/login#top", "https://example.com/login", "exact", "domain", "fragment differs"],
    ["https://example.com/a/../login", "https://example.com/login", "exact", "domain", "dot segments resolved"],
    ["https://example.com/login", "https://example.com/a/../login", "exact", "domain", "dot segments in the saved address resolved"],
    ["https://example.com/caf%C3%A9", "https://example.com/café", "exact", "domain", "non-ASCII path percent-encoded"],
    // regex (case-insensitive, tested against origin + path only)
    ["https://example.com/login", "^https://example\\.com/", "regex", "domain", "pattern matches"],
    ["https://evil.com/?https://example.com/", "example\\.com", "regex", "domain", "query is not tested"],
    ["https://evil.com/#example.org", "example\\.org", "regex", "domain", "fragment is not tested"],
    ["https://EXAMPLE.com/", "^https://example\\.com", "regex", "domain", "case-insensitive"],
    ["https://example.com/", "(a+)+$", "regex", "domain", "a nested quantifier runs in linear time"],
    ["https://example.com/", "[", "regex", "domain", "invalid pattern"],
    ["https://example.com/", "(?<=e)xample", "regex", "domain", "look-around is refused"],
    ["https://example.com:8443/app", "^https://example\\.com:8443/app$", "regex", "domain", "port is part of the origin"],
    ["https://example.com/", "^https://example\\.com/$", "regex", "domain", "path / included"],
    ["https://bücher.de/", "^https://xn--bcher-kva\\.de/", "regex", "domain", "the origin is in punycode"],
    ["https://k.example/", "K", "regex", "domain", "ASCII case folding: the Kelvin sign is not k"],
    ["https://example.com/login", "^https://example\\.com/", "default", "regex", "default → regex (the user's own login)"],
    // default → regex: a plain address (absolute http(s), written as it serializes, one trailing
    // "/" aside) is matched as its domain, never as a pattern (review M2)
    ["https://evil.example/https://bank.com", "https://bank.com", "default", "regex", "default → regex: a plain address is no pattern (phishing path)"],
    ["https://bankxcom.example/", "https://bank.com/", "default", "regex", "default → regex: a plain address is no pattern (dot as any character)"],
    ["https://www.bank.com/login", "https://bank.com", "default", "regex", "default → regex: a plain address matches its site"],
    ["https://bank.com/x", "https://bank.com/login/", "default", "regex", "default → regex: a plain address with a path matches its site"],
    ["https://bank.com/", "http://bank.com", "default", "regex", "default → regex: a plain http address matches its site"],
    ["https://bank.com/", "https://BANK.com", "default", "regex", "default → regex: not as it serializes (capitals): still a pattern"],
    ["https://bankxcom.example/", "bank.com", "default", "regex", "default → regex: no scheme: still a pattern (regexWarning names it)"],
    ["https://evil.example/https://bank.com", "https://bank.com", "regex", "domain", "an explicit pattern stays a pattern (regexWarning names it)"],
    ["https://evil.example/androidapp://com.bank", "androidapp://com.bank", "default", "regex", "default → regex: an app address is no pattern either"],
    // pages: only absolute http(s) addresses, no default scheme (review L4)
    ["data:,@bank.com/", "https://bank.com", "domain", "domain", "a data: page is no website"],
    ["mailto:x@bank.com", "https://bank.com", "host", "domain", "a mailto: address is no page"],
    ["javascript:alert(1)//@bank.com/", "https://bank.com", "domain", "domain", "a javascript: address is no page"],
    ["bank.com", "https://bank.com", "domain", "domain", "a page needs its scheme"],
    ["//bank.com/", "https://bank.com", "domain", "domain", "a scheme-relative page is no page"],
    ["bank.com/login", "^https://bank\\.com/", "regex", "domain", "no pattern matches a page without a scheme"],
    // patterns test at most 2048 bytes of origin and path; a longer page matches none (review I3)
    [longPage(2048), "^https://bank\\.com/a+$", "regex", "domain", "origin and path of 2048 bytes: tested"],
    [longPage(2049), "^https://bank\\.com/a+$", "regex", "domain", "origin and path over 2048 bytes: no pattern matches"],
    [longPage(2049), "^https://bank\\.com/", "regex", "domain", "over 2048 bytes: not even a prefix pattern"],
    [`https://bank.com/${"a".repeat(2100)}/evil`, "^https://bank\\.com/a+$", "regex", "domain", "a long path can't hide how it ends"],
    [`https://bank.com/${"a".repeat(2100)}/evil`, "https://bank.com", "domain", "domain", "other match types don't mind the length"],
    // never
    ["https://example.com/", "https://example.com", "never", "domain", "never matches"],
  ];
  /**
   * The same for a login in a vault somebody shared with the user (`allowRegex` false): its regular
   * expressions never count (written by somebody else, run on every page), also when "default"
   * resolves to one; its other websites match as usual. [page, saved url, match, defaultMatch, note]
   */
  const sharedMatchInputs = [
    ["https://example.com/login", "^https://example\\.com/", "regex", "domain", "shared vault: a regular expression never matches"],
    ["https://example.com/", ".*", "regex", "domain", "shared vault: nor does a catch-all pattern"],
    ["https://example.com/login", "^https://example\\.com/", "default", "regex", "shared vault: default → regex by the user's setting"],
    ["https://www.example.com/login", "https://example.com", "domain", "domain", "shared vault: domain"],
    ["https://www.example.com/login", "https://example.com", "default", "domain", "shared vault: default → domain"],
    ["https://www.example.com/x", "https://www.example.com", "host", "domain", "shared vault: host"],
    ["https://example.com/login/step2", "https://example.com/login", "starts_with", "domain", "shared vault: starts with"],
    ["https://example.com/login", "https://example.com/login", "exact", "domain", "shared vault: exact"],
    ["https://example.com/", "https://example.com", "never", "domain", "shared vault: never"],
    ["https://www.bank.com/login", "https://bank.com", "default", "regex", "shared vault: default → regex: a plain address matches its site"],
    ["https://evil.example/https://bank.com", "https://bank.com", "default", "regex", "shared vault: default → regex: a plain address is no pattern"],
    ["https://bankxcom.example/", "bank.com", "default", "regex", "shared vault: default → regex: a pattern never counts"],
  ];
  const urlMatchCases = [
    ...matchInputs.map(([page, url, match, defaultMatch, note]) => ({
      page, url, match, defaultMatch, allowRegex: true, expected: core.matchesUrl(page, url, match, defaultMatch, true), note,
    })),
    ...sharedMatchInputs.map(([page, url, match, defaultMatch, note]) => ({
      page, url, match, defaultMatch, allowRegex: false, expected: core.matchesUrl(page, url, match, defaultMatch, false), note,
    })),
  ];
  for (const c of urlMatchCases) {
    // The rules the cases exist for: no regular expression ever matches for a shared login (a plain
    // address under default → regex is its domain, not a pattern), a plain address under default →
    // regex never matches another site's page, an app address is never a website, and only
    // absolute http(s) addresses are pages.
    const viaDefault = c.match === "default" && c.defaultMatch === "regex";
    const pattern = c.match === "regex" || (viaDefault && !isPlainAddress(c.url));
    if (!c.allowRegex && c.expected && pattern) throw new Error(`the core lets a shared-vault regular expression match: ${c.note}`);
    if (viaDefault && isPlainAddress(c.url) && c.expected && core.baseDomain(new URL(c.page).hostname) !== core.baseDomain(new URL(c.url).hostname || "-")) {
      throw new Error(`the core runs a plain address as a pattern under default → regex: ${c.note}`);
    }
    if (c.url.startsWith("androidapp://") && c.expected) throw new Error(`the core matches an app address to a page: ${c.note}`);
    if (!/^https?:\/\//i.test(c.page) && c.expected) throw new Error(`the core matches a page that isn't an absolute http(s) address: ${c.note}`);
  }
  // matchUrls (many websites against one page) must give what matchesUrl gives, case by case.
  const byPage = Map.groupBy(urlMatchCases, (c) => `${c.page}\u0000${c.defaultMatch}`);
  for (const group of byPage.values()) {
    const { page, defaultMatch } = group[0];
    const got = core.matchUrls(page, defaultMatch, group.map((c) => ({ url: c.url, match: c.match, allowRegex: c.allowRegex })));
    group.forEach((c, i) => {
      if (got[i] !== c.expected) throw new Error(`matchUrls disagrees with matchesUrl: ${c.note}`);
    });
  }

  // What an entry is matched as (`resolveMatch`): it runs as a pattern exactly when this is "regex".
  /** [saved url, match, defaultMatch] */
  const resolveInputs = [
    ["https://bank.com", "default", "regex"], ["https://bank.com/login/", "default", "regex"], ["http://bank.com/a?b#c", "default", "regex"],
    ["https://BANK.com", "default", "regex"], ["bank.com", "default", "regex"], ["^https://bank\\.com/", "default", "regex"],
    ["https://bank.com", "regex", "domain"], ["https://bank.com", "default", "default"], ["https://bank.com", "default", "bogus"],
    ["https://bank.com", "default", "host"], ["https://bank.com", "exact", "regex"], ["https://bank.com", "never", "regex"],
    ["https://bank.com", "bogus", "regex"], ["androidapp://com.bank", "default", "regex"],
  ];
  const resolveMatchCases = resolveInputs.map(([url, match, defaultMatch]) => ({ url, match, defaultMatch, expected: core.resolveMatch(url, match, defaultMatch) }));

  /** [page, saved url, match, note] */
  const downgradeInputs = [
    ["http://example.com/", "https://example.com", "domain", "https login on an http page"],
    ["https://example.com/", "http://example.com", "domain", "upgrade is fine"],
    ["http://localhost:8080/", "https://localhost:8080", "domain", "localhost is exempt"],
    ["http://example.com/", "http://example.com", "domain", "both http"],
    ["http://192.168.1.10/", "https://192.168.1.10", "host", "LAN address is not exempt"],
    ["HTTP://EXAMPLE.com/", "https://example.com", "domain", "scheme case"],
    ["http://example.com/", "example.com", "domain", "saved without a scheme = https"],
    ["http://example.com/", "androidapp://example.com", "domain", "an app address is not https"],
    ["http://example.com/", "^https://example\\.com", "regex", "regex naming https"],
    ["http://example.com/", "example\\.com", "regex", "regex without a scheme"],
    ["http://localhost/x", "^https://localhost", "regex", "regex, localhost exempt"],
    ["http://localhostx/", "^https://", "regex", "regex, only localhost itself is exempt"],
    ["https://example.com/", "^https://", "regex", "https page"],
    ["HTTP://example.com/", "^HTTPS://example\\.com", "regex", "regex, case-insensitive"],
    ["bank.com", "https://bank.com", "domain", "a page without a scheme is no http page"],
    ["data:,@bank.com/", "https://bank.com", "domain", "a data: page"],
  ];
  const downgradeCases = downgradeInputs.map(([page, url, match, note]) => ({ page, url, match, expected: core.downgrade(page, url, match), note }));

  // Why the engine refuses a pattern (null: it runs). Linear time, so nothing is refused for
  // being slow; only for its size or for syntax it doesn't have.
  const regexErrorCases = [
    "(a+)+", "(.*a){10}", "(x*)*y", "(a|ab)*c", "(.|.)*X", "(a?){30}", "(a{2,3}){4}", "(a{2}){4}", "(?<n>a+)+", "(?:a|b)+",
    "a*b*c*d*e", "a*b*c*d", "(?:ab)+", "(ab)+", "a+b+", "(ab){2}", "(a+){1}", "[(a+)+]", "\\(a+\\)+", "x{,3}", "x{}", "a{2,}b{3,}c*d+",
    "^https://example\\.com/", "^https://(www\\.)?example\\.com/", "^https://[a-z]+\\.example\\.com/", "(?<=a)b+", "(?<!a)b+",
    "(a)\\1", "[", "\\p{L}", "[^à-ü]+$", "a{1000}{1000}", "x".repeat(300), "x".repeat(301),
  ].map((pattern) => ({ pattern, expected: core.regexError(pattern) ?? null }));

  // Why an explicit pattern can also match other websites (null: it pins its website, or the
  // engine refuses it and regexError says why). A warning for the item editors, never a refusal.
  const regexWarningCases = [
    "^https://example\\.com/", "^https?://example\\.com/", "^http(s)?://example\\.com/login$", "^HTTPS://EXAMPLE\\.com/",
    "^https://example\\.com$", "^https://example\\.com:8443/", "^https://example\\.com(/.*)?$", "^https://example\\.com(?::\\d+)?/",
    "^https://(www\\.)?example\\.com/", "^https://([a-z0-9-]+\\.)*example\\.com/", "^https://[^/]+\\.example\\.co\\.uk/",
    "^https://(www|login)\\.example\\.com/", "^https://192\\.168\\.1\\.10:8443/", "^https://a\\.example/|^https://b\\.example/",
    "example\\.com", "https://example\\.com/", "", ".*", "(?i)^https://example\\.com/", "^ftp://example\\.com/", "^https://example\\.com/|evil",
    "^https://example.com/", "^https://example\\.com", "^https://example\\.com/?", "^https://example\\.com\\b", "^https://.*\\.example\\.com/",
    "^https://[^.]+\\.example\\.com/", "^https://[a-z]+example\\.com/", "^https://([a-z]+\\.)*com/", "^https://[^/]+\\.co\\.uk/", "^https://[a-z]+/",
    "bank.com", "https://bank.com", "https://BANK.com", "(", "(?<=a)b",
  ].map((pattern) => ({ pattern, expected: core.regexWarning(pattern) ?? null }));

  // ------------------------------------------------------------ (c) save plan

  // Logins that match the page, in matching order. kinds: own = the user's own vault (writable),
  // shared = a vault somebody shared with write access, ro = a shared vault the user can only view.
  const own = (id, username, password) => ({ id, name: `Login ${id}`, username, password, writable: true, personal: true });
  const shared = (id, username, password, vault = "Team") => ({ id, name: `Login ${id}`, username, password, writable: true, personal: false, vault });
  const ro = (id, username, password, vault = "Family") => ({ id, name: `Login ${id}`, username, password, writable: false, personal: false, vault });

  /** [name, candidates, typed user name, typed password] */
  const saveInputs = [
    ["no password: nothing", [own("a", "alex", "old")], "alex", ""],
    ["rule 1: same user name already has the password", [own("a", "alex", "pw")], "alex", "pw"],
    ["rule 1: another login with that user name has the password", [own("a", "alex", "old"), own("b", "alex", "pw")], "alex", "pw"],
    ["rule 1: own login with the user name is updated", [own("b", "sam", "x"), own("a", "alex", "old")], " ALEX ", "new"],
    ["rule 1: only the user name was saved", [own("a", "alex", "")], "alex", "new"],
    ["rule 1: user names compare trimmed, without case", [own("a", "Alex@Example.com ", "old")], "  alex@example.COM", "new"],
    ["rule 1: passwords compare exactly", [own("a", "alex", "PW")], "alex", "pw"],
    ["rule 1: the first own login with the user name", [own("a", "alex", "one"), own("b", "alex", "two")], "alex", "three"],
    ["rule 1: shared login with the user name is offered, not selected", [shared("s", "alex", "old"), own("b", "sam", "x")], "alex", "new"],
    ["rule 1: own login selected, shared one offered after the own ones", [shared("s", "alex", "old"), own("a", "alex", "old2"), own("b", "sam", "x")], "alex", "new"],
    ["rule 1: shared login already has the password", [shared("s", "alex", "new")], "alex", "new"],
    ["rule 1: own login differs, shared one has the password", [own("a", "alex", "old"), shared("s", "alex", "new")], "alex", "new"],
    ["rule 1: view-only login with the user name is never offered", [ro("r", "alex", "old")], "alex", "new"],
    ["rule 1: view-only login with the password counts as saved", [ro("r", "alex", "pw")], "alex", "pw"],
    ["rule 1: view-only login with the user name, own login without one: new login", [ro("r", "alex", "old"), own("b", "", "x")], "alex", "new"],
    ["rule 1: shared login with the user name, own login without one: new login", [shared("s", "alex", "old"), own("b", "", "x")], "alex", "new"],
    ["rule 1: two shared logins with the user name, both offered", [shared("s1", "alex", "a"), shared("s2", "alex", "b", "Family")], "alex", "new"],
    ["rule 1: a shared vault without a name is labelled", [shared("s", "alex", "old", "")], "alex", "new"],
    ["rule 1: view-only and shared logins with the user name", [ro("r", "alex", "z"), shared("s", "alex", "y")], "alex", "new"],
    ["rule 1: everything at once", [own("a", "alex", "old"), own("b", "sam", "x"), shared("s", "alex", "y"), ro("r", "alex", "z")], "alex", "new"],
    ["rule 1, no user name typed: own login without a user name", [own("a", "", "old"), own("b", "alex", "x")], "", "new"],
    ["rule 1, no user name typed: whitespace is no user name", [own("a", "", "old")], "   ", "new"],
    ["rule 1, no user name typed: own login without a user name has the password", [own("a", "", "pw")], "", "pw"],
    ["rule 1, no user name typed: shared login without a user name never counts", [shared("s", "", "x"), own("a", "alex", "old")], "", "new"],
    ["rule 1, no user name typed: shared login without a user name has the password", [shared("s", "", "new")], "", "new"],
    ["rule 1, no user name typed: own login wins over a shared one", [shared("s", "", "x"), own("a", "", "old")], "", "new"],
    ["rule 2: own login without a user name gets it", [own("a", "", "old")], "alex", "new"],
    ["rule 2: even when the password is the same", [own("a", "", "pw")], "alex", "pw"],
    ["rule 2: the one with the typed password", [own("a", "", "one"), own("b", "", "two")], "alex", "two"],
    ["rule 2: else the first", [own("a", "", "one"), own("b", "", "two")], "alex", "three"],
    ["rule 2: shared login without a user name is never completed", [shared("s", "", "x")], "alex", "new"],
    ["rule 2: own login wins over a shared one that has the password", [shared("s", "", "new"), own("a", "", "old")], "alex", "new"],
    ["rule 2: view-only login without a user name is never completed", [ro("r", "", "pw"), own("b", "", "two")], "alex", "pw"],
    ["rule 2: no login without a user name: new login", [own("a", "sam", "x")], "alex", "pw"],
    ["rule 2: the same password under another user name is another account", [own("a", "sam", "pw")], "alex", "pw"],
    ["rule 2: nothing saved for the site", [], "alex", "pw"],
    ["rule 3: the password is already saved", [own("a", "alex", "pw"), own("b", "sam", "x")], "", "pw"],
    ["rule 3: the password is saved in a view-only vault", [ro("r", "alex", "pw")], "", "pw"],
    ["rule 3: the password is saved in a shared vault", [shared("s", "alex", "pw")], "", "pw"],
    ["rule 3: exactly one own login", [own("a", "alex", "old")], "", "new"],
    ["rule 3: one own login and a view-only one", [ro("r", "sam", "x"), own("b", "alex", "old")], "", "new"],
    ["rule 3: one own login and a shared one", [shared("s", "sam", "x"), own("a", "alex", "old")], "", "new"],
    ["rule 3: two own logins: new login", [own("a", "alex", "a"), own("b", "sam", "b")], "", "new"],
    ["rule 3: a shared login is never the only login", [shared("s", "alex", "x")], "", "new"],
    ["rule 3: a view-only login is never the only login", [ro("r", "alex", "old")], "", "new"],
    ["rule 3: nothing saved for the site", [], "", "pw"],
  ];

  const simpleTargets = (targets) => targets.map((t) => (t.vault ? { id: t.id, vault: t.vault } : { id: t.id }));
  const simplePlan = (p) => {
    if (p.action === "none") return { action: "none" };
    return p.action === "create"
      ? { action: "create", targets: simpleTargets(p.targets) }
      : { action: "update", reason: p.reason, target: p.target, targets: simpleTargets(p.targets) };
  };
  const savePlanCases = saveInputs.map(([name, candidates, typedUser, password]) => {
    const plan = core.planSave(candidates, typedUser, password);
    const expected = simplePlan(plan);
    // The security property the rule exists for (round 1, 2026-11-15): no plan ever selects a
    // login outside the user's own vault; shared ones are only offered.
    if (expected.action === "update" && !candidates.find((c) => c.id === expected.target)?.personal) {
      throw new Error(`the core's save plan selects a shared-vault login in "${name}"`);
    }
    // Only what the prompt offered is accepted as the answer ("new" always, while there is a plan).
    if (plan.action !== "none") {
      for (const answer of [plan.target, "new", ...plan.targets.map((t) => t.id)]) {
        if (core.chosenSaveTarget(plan, answer) !== answer) throw new Error(`chosenSaveTarget refuses "${answer}" in "${name}"`);
      }
      for (const c of candidates.filter((c) => !plan.targets.some((t) => t.id === c.id))) {
        if (core.chosenSaveTarget(plan, c.id) !== undefined) throw new Error(`chosenSaveTarget accepts "${c.id}", never offered, in "${name}"`);
      }
    }
    return { name, candidates, typedUser, password, expected };
  });

  // ------------------------------------------------------------ (d) passkey "Save in"

  const pk = (id, name, username, urls, kind = "own", vault) => ({
    id, name, username, urls, writable: kind !== "ro", personal: kind === "own", ...(kind === "own" ? {} : { vault: vault ?? "Team" }),
  });
  /** [name, logins, page host, RP ID, user name, display name] */
  const passkeyInputs = [
    ["own login for the exact host is preselected", [pk("a", "Example", "alex@example.com", ["https://login.example.com"])], "login.example.com", "example.com", "alex@example.com", "Alex"],
    ["shared login for the exact host: listed with its vault, never preferred", [pk("s", "Example", "alex@example.com", ["https://login.example.com"], "shared")], "login.example.com", "example.com", "alex@example.com", "Alex"],
    ["own logins first, then by exact host, user name, name",
      [
        pk("s", "AAA shared", "alex@example.com", ["https://login.example.com"], "shared"),
        pk("b", "Bravo", "sam", ["https://example.com"]),
        pk("c", "Charlie", "alex", ["https://example.com"]),
        pk("d", "Delta", "someone", ["https://login.example.com"]),
        pk("e", "Echo", "alex@example.com", ["https://login.example.com"]),
      ], "login.example.com", "example.com", "alex@example.com", "Alex"],
    ["RP ID host, subdomains of it; never a sibling outside it or another site",
      [
        pk("a", "Apex", "x", ["https://example.com"]),
        pk("b", "Sibling", "x", ["https://bazarr.example.com"]),
        pk("c", "Other site", "x", ["https://example.org"]),
        pk("d", "Lookalike", "x", ["https://notexample.com"]),
        pk("e", "Parent", "x", ["https://com"]),
      ], "cloudy.example.com", "example.com", "", ""],
    ["view-only logins are never targets", [pk("r", "Example", "alex", ["https://example.com"], "ro", "Family"), pk("a", "Mine", "alex", ["https://example.com"])], "example.com", "example.com", "alex", ""],
    ["display name matches a user name", [pk("a", "Alpha", "x", ["https://example.com"]), pk("b", "Bravo", "Alex Morgan", ["https://example.com"])], "example.com", "example.com", "", "Alex Morgan"],
    ["typed user name matches the local part of a saved address", [pk("a", "Alpha", "x", ["https://example.com"]), pk("b", "Bravo", "alex@mail.example", ["https://example.com"])], "example.com", "example.com", "alex", ""],
    ["website saved without a scheme, with a port, trailing dot or in capitals",
      [
        pk("a", "Alpha", "x", ["example.com"]),
        pk("b", "Bravo", "x", ["https://EXAMPLE.com:8443/login"]),
        pk("c", "Charlie", "x", ["https://example.com."]),
      ], "example.com", "example.com", "", ""],
    ["several websites: any one of them counts", [pk("a", "Alpha", "x", ["https://example.org", "https://login.example.com"])], "login.example.com", "example.com", "", ""],
    ["Unicode and punycode name the same host", [pk("a", "Bücher", "x", ["https://bücher.de"])], "xn--bcher-kva.de", "xn--bcher-kva.de", "", ""],
    ["names sort without regard to case", [pk("a", "bravo", "x", ["https://example.com"]), pk("b", "Alpha", "x", ["https://example.com"]), pk("c", "alpha", "x", ["https://example.com"])], "example.com", "example.com", "", ""],
    ["no logins: new login", [], "example.com", "example.com", "alex", "Alex"],
    ["only shared logins: nothing preferred", [pk("s", "Shared", "alex", ["https://example.com"], "shared"), pk("t", "Team two", "x", ["https://example.com"], "shared", "Family")], "example.com", "example.com", "alex", ""],
    ["an app website is not a website", [pk("a", "App", "x", ["androidapp://example.com"])], "example.com", "example.com", "", ""],
    ["an app website next to a real one", [pk("a", "App", "x", ["androidapp://login.example.com", "https://example.com"])], "login.example.com", "example.com", "", ""],
  ];
  const passkeyTargetCases = passkeyInputs.map(([name, logins, host, rpId, userName, displayName]) => {
    const t = core.passkeySaveTargets(logins, host, rpId, userName, displayName);
    const expectedDefault = core.passkeyDefaultTarget(t);
    // The preselected choice: the first preferred target (only ever the user's own), else a new login.
    if (expectedDefault !== (t.find((x) => x.preferred)?.id ?? "new")) throw new Error(`passkeyDefaultTarget disagrees in "${name}"`);
    if (t.some((x) => x.preferred && !logins.find((l) => l.id === x.id)?.personal)) throw new Error(`a shared login is preferred in "${name}"`);
    return {
      name, logins, host, rpId, userName, displayName,
      expected: t.map((x) => ({ id: x.id, preferred: x.preferred, ...(x.vault ? { vault: x.vault } : {}) })),
      expectedDefault,
    };
  });

  // ------------------------------------------------------------ (e) RP ID

  /** [origin, requested RP ID (null = none), note] */
  const rpInputs = [
    ["https://login.example.com", null, "defaults to the origin's host"],
    ["https://login.example.com", "example.com", "registrable parent"],
    ["https://login.example.com", "login.example.com", "the host itself"],
    ["https://login.example.com", "EXAMPLE.com", "canonical lower case"],
    ["https://login.example.com:8443", "example.com", "port ignored"],
    ["https://login.example.com", "other.com", "another site"],
    ["https://example.com", "ample.com", "not a label suffix"],
    ["https://evil-example.com", "example.com", "not a label suffix"],
    ["https://login.example.com", "com", "single-label public suffix"],
    ["https://a.example.co.uk", "co.uk", "multi-label public suffix"],
    ["https://a.example.co.uk", "example.co.uk", "registrable under a multi-label suffix"],
    ["https://home.duckdns.org", "duckdns.org", "dynamic DNS suffix"],
    ["https://home.duckdns.org", "home.duckdns.org", "dynamic DNS name"],
    ["https://nas.myfritz.net", "myfritz.net", "myfritz.net is a public suffix"],
    ["https://x.nas.myfritz.net", "nas.myfritz.net", "a name under myfritz.net"],
    ["https://home.myds.me", "myds.me", "myds.me is a public suffix"],
    ["https://a.dedyn.io", "dedyn.io", "dedyn.io is a public suffix"],
    ["https://app.cloudapp.net", "cloudapp.net", "cloudapp.net is a public suffix"],
    ["https://ec2-1-2-3-4.us-east-2.compute.amazonaws.com", "us-east-2.compute.amazonaws.com", "EC2 region (wildcard rule)"],
    ["https://ec2-1-2-3-4.us-east-2.compute.amazonaws.com", "compute.amazonaws.com", "above the EC2 regions"],
    ["https://x.foo.ck", "foo.ck", "wildcard rule *.ck"],
    ["https://a.b.internal", "b.internal", "unknown top-level domain"],
    ["http://example.com", null, "plain http"],
    ["http://localhost:8080", null, "localhost over http"],
    ["http://localhost:8080", "localhost", "localhost"],
    ["http://app.localhost", "localhost", "subdomain of localhost"],
    ["https://192.168.1.10", null, "IP address origin"],
    ["https://[::1]", null, "IPv6 origin"],
    ["https://Login.example.com", null, "origin not in canonical form"],
    ["https://login.example.com", "example.com.", "trailing dot"],
    ["https://login.example.com", "", "empty"],
    ["https://login.example.com", "exa mple.com", "whitespace"],
    ["https://login.example.com", "example.com:443", "port in the RP ID"],
    ["https://login.example.com", "*.example.com", "wildcard"],
    ["https://login.example.com", "1.2.3.4", "IP address RP ID"],
    ["https://login.example.com/", null, "origin with a path"],
    ["android:apk-key-hash:abc", null, "an app's origin is not a web origin"],
    ["https://xn--bcher-kva.de", "bücher.de", "Unicode RP ID is punycoded"],
    ["https://login.xn--bcher-kva.de", "xn--bcher-kva.de", "punycode parent"],
    ["https://xn--strae-oqa.de", "straße.de", "UTS #46 keeps ß"],
  ];
  const rpIdCases = rpInputs.map(([origin, requested, note]) => {
    try {
      return { origin, requested, expected: core.effectiveRpId(requested ?? undefined, origin), note };
    } catch (e) {
      return { origin, requested, expected: null, error: e.name, message: e.message, note };
    }
  });
  for (const c of rpIdCases) {
    if (c.expected === null && c.error !== "SecurityError") throw new Error(`effectiveRpId threw ${c.error}, not a SecurityError: ${c.note}`);
  }

  // ------------------------------------------------------------ (f) sign-in request phrases

  // Fixed per key and count: the real phrase among decoys derived from the key.
  const choiceKeys = ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk", "__________________________________________8"];
  const phraseChoiceCases = choiceKeys.flatMap((publicKey) =>
    [2, 3, 5].map((count) => {
      const expected = core.loginPhraseChoices(publicKey, count);
      if (JSON.stringify(core.loginPhraseChoices(publicKey, count)) !== JSON.stringify(expected)) throw new Error("loginPhraseChoices isn't fixed per key");
      if (expected.filter((c) => c === core.loginPhrase(publicKey)).length !== 1) throw new Error("loginPhraseChoices lacks the real phrase");
      return { publicKey, count, expected };
    }),
  );

  return {
    version: 2,
    about: "Golden vectors from the Rust core (crates/core/src/site, through its WASM build). Regenerate: node testdata/generate-vectors.mjs",
    publicSuffixList: core.publicSuffixListVersion(),
    normalizeHost: normalizeHostCases,
    baseDomain: baseDomainCases,
    publicSuffix: publicSuffixCases,
    urlMatch: urlMatchCases,
    resolveMatch: resolveMatchCases,
    downgrade: downgradeCases,
    regexError: regexErrorCases,
    regexWarning: regexWarningCases,
    savePlan: savePlanCases,
    passkeyTargets: passkeyTargetCases,
    rpId: rpIdCases,
    loginPhraseChoices: phraseChoiceCases,
  };
}

/** A page address of `len` bytes on https://bank.com/. */
function longPage(len) {
  const base = "https://bank.com/";
  return base + "a".repeat(len - base.length);
}

/**
 * An absolute address written as it serializes, one trailing "/" aside: an http(s) one, or another
 * scheme's with "://" (an app's). The core's rule for entries that are never patterns.
 */
function isPlainAddress(s) {
  let u;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  const less = (x) => (x.endsWith("/") ? x.slice(0, -1) : x);
  return (u.protocol === "http:" || u.protocol === "https:" || s.includes("://")) && less(u.href) === less(s);
}

// ------------------------------------------------------------ string arguments (review L1)

function checkStringArguments(core, memory, dts) {
  const code = dts.replace(/\/\*[\s\S]*?\*\//g, "");
  const signatures = [];
  for (const m of code.matchAll(/^export function (\w+)\((.*)\): .+;$/gm)) {
    signatures.push({ owner: null, name: m[1], params: params(m[2]) });
  }
  for (const m of code.matchAll(/^export class (\w+) \{\n([\s\S]*?)\n\}/gm)) {
    for (const line of m[2].split("\n")) {
      const member = /^\s+(static )?(\w+)\((.*)\)(?:: .+)?;$/.exec(line);
      if (member) signatures.push({ owner: m[1], static: !!member[1], name: member[2], params: params(member[3]) });
    }
  }
  if (signatures.length < 50) throw new Error(`only ${signatures.length} exports found in passauth_core.d.ts`);

  // One handle of every class, for `this` and for parameters typed with a class.
  const bytes = (b) => new Uint8Array(64).fill(b);
  const contact = core.accountFromSessionBytes("contact", bytes(7));
  const grantor = core.accountFromSessionBytes("grantor", bytes(9));
  const request = core.LoginRequestKey.generate();
  const approval = grantor.approveLoginRequest(request.publicKey(), "req", request.phrase());
  const emergency = grantor.newEmergencyKey("grant");
  const instances = {
    Account: contact,
    VaultKey: contact.newVaultKey("vault").takeKey(),
    EmergencyKey: emergency.takeKey(),
    LoginRequestKey: request,
    ApprovedLogin: request.open(approval.sealed, "grantor", "req"),
    FileEncryptor: new core.FileEncryptor(core.fileNewKey(), "item", "file"),
    FileDecryptor: new core.FileDecryptor(core.fileNewKey(), "item", "file"),
    // The core's KDF floor: the one slow fixture (OPAQUE functions take master keys).
    MasterKeys: core.deriveMasterKeys("password", undefined, "account", { memory_kib: 65536, iterations: 3, parallelism: 1, salt: "AAAAAAAAAAAAAAAAAAAAAA" }, false),
  };
  const isString = (type) => /^string( \| null)?( \| undefined)?$/.test(type);
  const placeholder = (type) => {
    if (isString(type)) return "x";
    if (type === "boolean") return false;
    if (/^number\b/.test(type)) return 0;
    if (/Uint8Array/.test(type)) return new Uint8Array(0);
    if (/^[A-Z]\w*$/.test(type) && typeof core[type] === "function") {
      if (!instances[type]) throw new Error(`no ${type} handle for the string-argument check: add one to \`instances\``);
      return instances[type];
    }
    return undefined;
  };
  const wrong = [5, 1.5, Number.NaN, 5n, true, false, {}, [], ["x"], { length: 3 }, { length: 2 ** 31 - 1 }, { length: 2 ** 32 - 1 }, Symbol("s"), Object("x")];

  const before = memory.buffer.byteLength;
  let checks = 0;
  for (const sig of signatures) {
    const label = sig.owner ? `${sig.owner}.${sig.name}` : sig.name;
    sig.params.forEach((param, at) => {
      if (!isString(param.type)) return;
      const optional = param.optional || /\| (null|undefined)/.test(param.type);
      for (const bad of optional ? wrong : [...wrong, null, undefined]) {
        const args = sig.params.map((p, i) => (i === at ? bad : placeholder(p.type)));
        let error;
        try {
          if (!sig.owner) core[sig.name](...args);
          else if (sig.name === "constructor") Reflect.construct(core[sig.owner], args);
          else if (sig.static) core[sig.owner][sig.name](...args);
          else {
            const self = instances[sig.owner];
            if (!self) throw new Error(`no ${sig.owner} handle for the string-argument check: add one to \`instances\``);
            self[sig.name](...args);
          }
        } catch (e) {
          error = e;
        }
        if (!(error instanceof Error) || error.constructor !== Error || error.message !== "expected a string") {
          throw new Error(`${label}(${param.name} = ${describe(bad)}) did not throw Error("expected a string"): ${error?.constructor?.name}: ${error?.message ?? "returned"}`);
        }
        checks++;
      }
    });
  }
  if (checks < 500) throw new Error(`only ${checks} string-argument checks ran`);
  if (memory.buffer.byteLength !== before) {
    throw new Error(`WASM memory grew from ${before} to ${memory.buffer.byteLength} bytes during the string-argument check`);
  }
  // The instance still works.
  const key = core.sendNewKey();
  if (core.sendDecrypt(key, "data", core.sendEncrypt(key, "data", "still fine ✓")) !== "still fine ✓") {
    throw new Error("the WASM instance broke during the string-argument check");
  }
  for (const handle of Object.values(instances)) handle.free();
  emergency.free();
  grantor.free();
}

/** `a: string, b?: number | null` → [{ name, optional, type }], split at the top level only. */
function params(list) {
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i <= list.length; i++) {
    const c = list[i];
    if (c === "{" || c === "[" || c === "(" || c === "<") depth++;
    else if (c === "}" || c === "]" || c === ")" || c === ">") depth--;
    else if ((c === "," && depth === 0) || i === list.length) {
      const part = list.slice(start, i).trim();
      if (part) {
        const m = /^(\w+)(\?)?: (.+)$/.exec(part);
        if (!m) throw new Error(`can't read the parameter "${part}" in passauth_core.d.ts`);
        out.push({ name: m[1], optional: !!m[2], type: m[3] });
      }
      start = i + 1;
    }
  }
  return out;
}

function describe(v) {
  if (typeof v === "symbol" || typeof v === "bigint") return String(v) + (typeof v === "bigint" ? "n" : "");
  if (v instanceof String) return "new String()";
  return JSON.stringify(v) ?? String(v);
}
