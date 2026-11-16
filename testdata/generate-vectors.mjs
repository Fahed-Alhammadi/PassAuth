// Golden vectors for the site logic every PassAuth client uses: host names, public suffixes and
// base domains (the full Public Suffix List), website matching (`allowRegex`: false for a login in
// a vault somebody shared, whose regular expressions never count), the https→http downgrade rule,
// the regular-expression engine's refusals and warnings, the save rule, passkey "Save in" targets
// and RP ID checks. Also the phrases an approving app offers for a sign-in request
// (`loginPhraseChoices`), which must be the same on every device and in every binding, and signed
// sharing (`signedSharing`: identities and their XEdDSA cross-signatures, share signatures, member
// rosters, reviews and chains, key ids, key pins, key epoch pins and vault admission; byte-exact,
// cross-checked here independently of the core with node:crypto and BigInt arithmetic).
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
import { createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, sign, verify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { domainToASCII, fileURLToPath, pathToFileURL } from "node:url";

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
    signedSharing: signedSharingVectors(core),
  };
}

// ------------------------------------------------------------ (g) signed sharing

/**
 * Signed sharing (crates/core/src/sharing.rs): identities with their XEdDSA cross-signatures,
 * share signatures, member rosters (reviewed, chained, within the hierarchy), member reviews,
 * key ids, key epoch pins, vault admission, tombstones and the account's own identity. Fixed
 * accounts (session bytes) with signing identity records made once (their wrapped keys and
 * XEdDSA signatures have random nonces, so they are inputs here); Ed25519 signatures are
 * deterministic, so every share signature and roster below is exact. Independently of the core,
 * this script opens the fixtures' XChaCha20-Poly1305 wraps (HChaCha20 here, ChaCha20-Poly1305 from
 * node:crypto: the vault key, the v1 and v2 account-wrap formats, the Ed25519 seeds), rebuilds
 * every canonical byte string, hashes identities with SHA-256, verifies every signature with
 * node:crypto Ed25519, computes XEdDSA (Signal's spec, BigInt Edwards arithmetic) and the
 * X25519 → Ed25519 key conversion, the HKDF/HMAC key commitments, key ids and member-list
 * digests, and signs the rogue rosters itself (rosters the core refuses to sign).
 */
function signedSharingVectors(core) {
  const fixtures = {
    accounts: [
      {
        name: "alice",
        id: "00000000-0000-4000-8000-00000000000a",
        sessionBytes: "EREREREREREREREREREREREREREREREREREREREREREhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhIQ",
        record: {
          signing_key: "4_se49fqgfE7pVNSq1SjIfKFyhDt7elWrb2sB3kuKBI",
          identity_signature: "c-nWl4l8aKoBU0Ia3puW08ER0YvZQdamOFdRWu80e6rqvhWVCEKpBBJ3XRYQb62PmQLTbqZW7eThBpbc00F8Ag",
          x25519_signature: "fp4q4qE6_iuQC3SNfJnHl0XV4n2RkL0KltJ6SjHJcL4eA4VERe_VBroSxnZ1t0SpxouVUj8AaRsmllcI-UE_Bw",
          wrapped_signing_key: "ARPdisrbaBMgaNRUUtOFI9l7vCzcYTWSmaHoxeTCvYIJsnQJ790EbSBQObZ8wbckwYkwTVL7uYzIvgNLU1VjH0uQA2aUFJLLpw",
        },
      },
      {
        name: "bob",
        id: "00000000-0000-4000-8000-00000000000b",
        sessionBytes: "EhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg",
        record: {
          signing_key: "8BnSHCGxjasEtmd6v59cR_gIc9jYNDCHBWO3Qe7jwk4",
          identity_signature: "IIqZ2m--CWOr98EXA-jTPlsNYb8EwQXP6wCC9yFFwxFzVd35KdcCaJwL4e76Z2172nk130NPXnvm3uCbeN2PCA",
          x25519_signature: "KSnEsftdqL39YN9Xsj3WuJhsnDHlJjOutSjpJo9Hcvy-sV2A0IkRpJJBMmzBM6dsSuItDgg2uM2aM6X0MgTPBA",
          wrapped_signing_key: "AVWC5aaBvBAtJMX-IGX-UJSwvdHMK7qbpXHcoQJdvm-kyFmyr4UUhygrzA6YWDSXYnwoN-Bnl3m0Arl-ksPTcj4S3W9CnCQk5A",
        },
      },
      {
        name: "carol",
        id: "00000000-0000-4000-8000-00000000000c",
        sessionBytes: "ExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw",
        record: {
          signing_key: "1PpeglDfMKuLluHLdSxb0Ezx8RDTQJlbjyDmBJTtl9g",
          identity_signature: "TgUz8_dAPImnkIPOTdDSXEn0j9fO-uFu-LV1G3AVSo_D_mf6MZBvVdRrH2fhet0YBPDz8Ewbi5OXjje5iolECw",
          x25519_signature: "uXNmm8P0CLBFKkWNOfjP4atSXHm0hLNS2tjMe4TGtVKl4Jg_lAa3IMFfktgOk7KACt5AV5bp2wA5IjveLcz2Ag",
          wrapped_signing_key: "AX5aGLDq_vX9HN-6Oe3dovOzkNVYQEbxpdCZnd-OX6xGKU2waluSD2y4oktYEkf9K3ChY27R-UVXnuTuCYG3U-tub3zLVj2Eug",
        },
      },
      {
        name: "dave",
        id: "00000000-0000-4000-8000-00000000000d",
        sessionBytes: "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJA",
        record: {
          signing_key: "wYHJl2-xdKtNPgkwuBDJjYb-NM9sCzLOKmm-zJSVQ04",
          identity_signature: "cf4dNwGfkH9JSY6Dlgw4bxsKJPdHROMe7qwNOeZXWq3YbkAGOxFuJHEAqHvWW13HCA61a5HPcJJzwvBs9UYOCw",
          x25519_signature: "1hE-TqLL76zolykglRv1QxFE2fHaGpCPH86e1g0ChTWHdFm0o1qqESTIH6Za7qhStMYpvgcq-3_R8HrM3QzfBw",
          wrapped_signing_key: "AWfph2KYDZSTwYU3xmL4F08Ao6AEAqueEW_QmnCGssL-0dWQ6pN4HKYiXwQKTj6BdXLHJqVR_xHShVngGaEAaFj24LR38xZRPw",
        },
      },
    ],
    // Alice's vault and its key wrapped by her account key (`key_kind` "account"): the v1 format
    // (no epoch; what the apps write for now), the same key as an epoch-bound v2 wrap at epoch 0
    // (`0x02` marker), and a second key (v2, epoch 0).
    vault: {
      id: "00000000-0000-4000-8000-0000000000f1",
      wrappedKey: "AQs7dp_yGNEe99qnqxT8pN9dvgEhLyJRcWpUjBluEUFH3CVdXlMfITiXXpNTEV9fHjEmGhQSNerShBKEOFIPOXbaDLwqbR7P-w",
      wrappedKeyV2: "AgGEHEeD0CxCeYFbiwpGGMuD15WYUlW8GNg-UDzS6GdMGzViWqsNjOwuh6T9SG1pkNu3bsOlJM4_f70RBmdL3HWZ_T1R-q7kAPw",
      secondKeyV2: "AgG2cM-1aLbVhPZ9Rfx-0DwxTd37hQH1r8skoQWRYUhd7cWkzQMuotYHJgOZDq02HV613pwUBjuyUkmjtFT50AX8Udh9guNIdYg",
    },
    // XEdDSA with a fixed nonce (the apps use 64 random bytes): Carol's X25519 secret.
    xeddsa: { message: "passauth XEdDSA test vector", z: "5a".repeat(64) },
  };
  const b64 = (u8) => Buffer.from(u8).toString("base64url");
  const unb64 = (s) => Buffer.from(s, "base64url");
  const sha256 = (b) => createHash("sha256").update(b).digest();
  const field = (b) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    return Buffer.concat([len, Buffer.from(b)]);
  };
  const text = (s) => field(Buffer.from(s, "utf8"));
  const num = (n) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    return field(b);
  };
  const canon = (tag, parts) => Buffer.concat([text(tag), ...parts]);
  const ed25519Verify = (signingKey, message, signature) =>
    verify(null, message, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: signingKey }, format: "jwk" }), unb64(signature));
  // A thrown Error's message is the core's error code, or its description.
  const outcome = (f) => {
    try {
      return { expected: f() };
    } catch (e) {
      return { error: e.message };
    }
  };
  const must = (cond, what) => {
    if (!cond) throw new Error(what);
  };

  // --- Independent primitives: XChaCha20-Poly1305 opening, XEdDSA, HKDF/HMAC.
  const hchacha20 = (key, nonce16) => {
    const s = new Uint32Array(16);
    s.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(4 * i);
    for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(4 * i);
    const rotl = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
    const qr = (a, b, c, d) => {
      s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
      s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
      s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
      s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
    };
    for (let i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = Buffer.alloc(32);
    [0, 1, 2, 3, 12, 13, 14, 15].forEach((w, i) => out.writeUInt32LE(s[w], 4 * i));
    return out;
  };
  // `version (1) ‖ nonce (24) ‖ ciphertext ‖ tag (16)`, as crates/core/src/crypto.rs writes it
  // (after the `0x02` marker of a v2 account wrap, which `marked` strips).
  const xopen = (key, blob, aad, marked = false) => {
    let b = unb64(blob);
    if (marked) {
      must(b[0] === 2, "a v2 account wrap without its marker");
      b = b.subarray(1);
    }
    must(b[0] === 1, "unknown ciphertext version");
    const nonce = b.subarray(1, 25);
    const d = createDecipheriv("chacha20-poly1305", hchacha20(key, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)]), { authTagLength: 16 });
    d.setAAD(Buffer.from(aad, "utf8"));
    d.setAuthTag(b.subarray(b.length - 16));
    return Buffer.concat([d.update(b.subarray(25, b.length - 16)), d.final()]);
  };
  const P = 2n ** 255n - 19n;
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const mod = (a, m = P) => ((a % m) + m) % m;
  const pow = (b, e, m = P) => {
    let r = 1n;
    b = mod(b, m);
    for (; e > 0n; e >>= 1n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
    }
    return r;
  };
  const inv = (a, m = P) => pow(a, m - 2n, m);
  const Dc = mod(-121665n * inv(121666n));
  const B = [15112221349535400772501151409588531511454012693041857206046113283949847762202n, 46316835694926478169428394003475163141307993866256225615783033603165251855960n];
  const add = ([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) => {
    const a = mod((Y1 - X1) * (Y2 - X2)), b = mod((Y1 + X1) * (Y2 + X2)), c = mod(2n * Dc * T1 * T2), d = mod(2n * Z1 * Z2);
    const e = b - a, f = d - c, g = d + c, h = b + a;
    return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  };
  const mulBase = (k) => {
    let r = [0n, 1n, 1n, 0n];
    for (let q = [B[0], B[1], 1n, mod(B[0] * B[1])]; k > 0n; k >>= 1n, q = add(q, q)) if (k & 1n) r = add(r, q);
    return r;
  };
  const le = (buf) => BigInt("0x" + (Buffer.from(buf).reverse().toString("hex") || "0"));
  const toLe = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex").reverse();
  const compress = ([X, Y, Z]) => {
    const zi = inv(Z);
    const out = toLe(mod(Y * zi));
    out[31] |= Number(mod(X * zi) & 1n) << 7;
    return out;
  };
  const sha512 = (...parts) => createHash("sha512").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
  const xeddsaSign = (secret, message, z) => {
    const c = Buffer.from(secret);
    c[0] &= 248;
    c[31] &= 127;
    c[31] |= 64;
    const k = mod(le(c), L);
    const a = compress(mulBase(k))[31] >> 7 ? mod(-k, L) : k;
    const A = compress(mulBase(a));
    const prefix = Buffer.alloc(32, 0xff);
    prefix[0] = 0xfe;
    const r = mod(le(sha512(prefix, toLe(a), message, z)), L);
    const R = compress(mulBase(r));
    const h = mod(le(sha512(R, A, message)), L);
    return { signature: Buffer.concat([R, toLe(mod(r + h * a, L))]), A };
  };
  // XEdDSA's convert_mont: the Edwards key with y = (u − 1)/(u + 1), sign bit 0.
  const montToEdwards = (u) => {
    const n = le(u);
    must(n < P, "non-canonical u");
    return toLe(mod((n - 1n) * inv(n + 1n)));
  };
  const hkdf = (key, info) => Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), Buffer.from(info), 32));
  const hmac = (key, msg) => createHmac("sha256", key).update(msg).digest();

  const accounts = {};
  const signers = {};
  const edKeys = {};
  for (const a of fixtures.accounts) {
    accounts[a.name] = core.accountFromSessionBytes(a.id, unb64(a.sessionBytes));
    signers[a.name] = accounts[a.name].openSigningIdentity(a.record);
    const seed = xopen(unb64(a.sessionBytes).subarray(0, 32), a.record.wrapped_signing_key, `passauth/signing-key/v1/${a.id}`);
    edKeys[a.name] = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: b64(seed), x: a.record.signing_key }, format: "jwk" });
  }
  const full = (name) => signers[name].publicIdentity();
  const legacy = (name) => accounts[name].legacyIdentity();
  const who = (name, isLegacy) => (isLegacy ? legacy(name) : full(name));
  const vaultId = fixtures.vault.id;
  const aliceKey = unb64(fixtures.accounts[0].sessionBytes).subarray(0, 32);

  // The vault key: the v1 and v2 wraps hold the same key; v2 binds the epoch.
  const rawKey = xopen(aliceKey, fixtures.vault.wrappedKeyV2, `passauth/vault-key/v2/${vaultId}/0`, true);
  must(rawKey.equals(xopen(aliceKey, fixtures.vault.wrappedKey, `passauth/vault-key/v1/${vaultId}`)), "the v1 and v2 wraps hold different keys");
  const rawKey2 = xopen(aliceKey, fixtures.vault.secondKeyV2, `passauth/vault-key/v2/${vaultId}/0`, true);
  const vaultKey = accounts.alice.openVaultKey(vaultId, fixtures.vault.wrappedKeyV2, "account", 0, false);
  const vaultKey2 = accounts.alice.openVaultKey(vaultId, fixtures.vault.secondKeyV2, "account", 0, false);
  // The apps write v1 for now (released apps read only that).
  must(xopen(aliceKey, vaultKey.wrapFor(accounts.alice, vaultId), `passauth/vault-key/v1/${vaultId}`).equals(rawKey), "wrapFor doesn't write a v1 wrap");
  const openings = [
    ["wrappedKey", 0, false],
    ["wrappedKey", 0, true],
    ["wrappedKey", 5, true],
    ["wrappedKeyV2", 0, false],
    ["wrappedKeyV2", 1, true],
  ].map(([wrap, keyEpoch, legacyAllowed]) => ({
    wrap,
    keyEpoch,
    legacyAllowed,
    ...outcome(() => {
      const k = accounts.alice.openVaultKey(vaultId, fixtures.vault[wrap], "account", keyEpoch, legacyAllowed);
      const id = k.keyId(vaultId);
      k.free();
      return id;
    }),
  }));

  // Key ids and commitments: HMAC-SHA256 under an HKDF-SHA256 subkey of the vault key.
  const keyIdOf = (raw) => b64(hmac(hkdf(raw, "passauth/vault-key-id/v1"), canon("passauth/vault-key-id/v1", [text(vaultId)])));
  const commitmentOf = (raw, keyEpoch) =>
    b64(hmac(hkdf(raw, "passauth/vault-key-commitment/v1"), canon("passauth/vault-key-commitment/v1", [text(vaultId), num(keyEpoch)])));
  must(vaultKey.keyId(vaultId) === keyIdOf(rawKey) && vaultKey2.keyId(vaultId) === keyIdOf(rawKey2), "a key id differs");
  const keyIds = { first: keyIdOf(rawKey), second: keyIdOf(rawKey2) };
  const commitmentCases = [0, 1, 2, 9007199254740991].map((keyEpoch) => {
    const commitment = vaultKey.commitment(vaultId, keyEpoch);
    must(commitment === commitmentOf(rawKey, keyEpoch), "a key commitment differs");
    return { keyEpoch, commitment };
  });

  // XEdDSA: a fixed-nonce signature made here, and every identity's cross-signature.
  const carolSecret = unb64(fixtures.accounts[2].sessionBytes).subarray(32);
  const fixed = xeddsaSign(carolSecret, Buffer.from(fixtures.xeddsa.message), Buffer.from(fixtures.xeddsa.z, "hex"));
  must(fixed.A.equals(montToEdwards(unb64(full("carol").public_key))), "XEdDSA's Edwards key isn't the X25519 key's");
  must(ed25519Verify(b64(fixed.A), Buffer.from(fixtures.xeddsa.message), b64(fixed.signature)), "the XEdDSA vector doesn't verify");
  const xeddsa = { ...fixtures.xeddsa, secret: carolSecret.toString("hex"), publicKey: full("carol").public_key, edwardsKey: b64(fixed.A), signature: b64(fixed.signature) };

  // Identities.
  const identityHash = (p) =>
    sha256(canon("passauth/identity-hash/v1", [text(p.user_id), field(unb64(p.public_key)), field(p.signing_key ? unb64(p.signing_key) : Buffer.alloc(0))]));
  const identities = fixtures.accounts.map(({ name }) => {
    const pub = full(name);
    const info = core.verifyIdentity(pub);
    const statement = canon("passauth/identity/v1", [text(pub.user_id), field(unb64(pub.public_key)), field(unb64(pub.signing_key))]);
    must(ed25519Verify(pub.signing_key, statement, pub.identity_signature), `${name}'s identity signature doesn't verify independently`);
    const edwardsKey = b64(montToEdwards(unb64(pub.public_key)));
    must(ed25519Verify(edwardsKey, statement, pub.x25519_signature), `${name}'s X25519 cross-signature doesn't verify independently`);
    must(info.hash === b64(identityHash(pub)) && info.legacy_hash === b64(identityHash(legacy(name))), `${name}'s identity hash differs`);
    must(core.verifyIdentity(legacy(name)).hash === info.legacy_hash, "legacy hash differs");
    // Without the cross-signature, or with another account's, it isn't an identity.
    must(outcome(() => core.verifyIdentity({ ...pub, x25519_signature: null })).error?.startsWith("malformed"), "an identity without its cross-signature verified");
    return { name, publicIdentity: pub, legacyIdentity: legacy(name), statement: statement.toString("hex"), edwardsKey, hash: info.hash, legacyHash: info.legacy_hash, fingerprint: info.fingerprint };
  });
  // The forged upgrade (review H1): Bob's id and X25519 key, Carol's signing key and signatures.
  const forgedUpgrade = { ...full("carol"), user_id: full("bob").user_id, public_key: full("bob").public_key };
  must(outcome(() => core.verifyIdentity(forgedUpgrade)).error === "bad_signature", "a forged upgrade verified");

  // Share signatures (the sealed key is any text: its SHA-256 is signed).
  const shareInputs = [
    ["alice", "bob", false, "write", 0, "c2VhbGVkLWtleS0x"],
    ["alice", "bob", true, "read", 0, "c2VhbGVkLWtleS0x"],
    ["alice", "carol", false, "admin", 7, "AQID"],
    ["bob", "carol", true, "read", 9007199254740991, ""],
    ["bob", "alice", false, "owner", 1, "c2VhbGVkLWtleS0y"],
  ];
  const shares = shareInputs.map(([signer, recipient, recipientLegacy, role, keyEpoch, sealedKey]) => {
    const to = who(recipient, recipientLegacy);
    const signature = signers[signer].signShare(vaultId, to, role, keyEpoch, sealedKey);
    const statement = canon("passauth/share/v1", [text(vaultId), text(to.user_id), field(identityHash(to)), text(role), num(keyEpoch), field(sha256(Buffer.from(sealedKey, "utf8"))), text(full(signer).user_id)]);
    must(ed25519Verify(full(signer).signing_key, statement, signature), "a share signature doesn't verify independently");
    core.verifyShare(vaultId, to, role, keyEpoch, sealedKey, full(signer), signature);
    // A share to the legacy identity also verifies for the account with a signing key.
    if (recipientLegacy) core.verifyShare(vaultId, full(recipient), role, keyEpoch, sealedKey, full(signer), signature);
    const changed = [[role === "read" ? "write" : "read", keyEpoch, sealedKey], [role, keyEpoch, `${sealedKey}x`]];
    if (keyEpoch < 9007199254740991) changed.push([role, keyEpoch + 1, sealedKey]);
    for (const [r, e, s] of changed) {
      must(outcome(() => core.verifyShare(vaultId, to, r, e, s, full(signer), signature)).error === "bad_signature", "a changed share didn't fail with bad_signature");
    }
    return { signer, recipient, recipientLegacy, vaultId, role, keyEpoch, sealedKey, statement: statement.toString("hex"), signature };
  });

  // Member rosters. Members: [name, role, input legacy, listed legacy (default: the input's)].
  // Valid ones go through the core (review, then sign what was reviewed) and must equal the roster
  // built and signed here; rogue ones (which the core refuses to sign) are signed here only.
  const entriesOf = (members) =>
    members
      .map(([name, role, inLegacy, listedLegacy]) => ({ user_id: full(name).user_id, identity: b64(identityHash(who(name, listedLegacy ?? inLegacy))), role }))
      .sort((x, y) => Buffer.compare(Buffer.from(x.user_id), Buffer.from(y.user_id)));
  const rosterBytes = (r) =>
    canon("passauth/member-roster/v1", [
      text(r.vault_id), num(r.version), num(r.key_epoch), field(unb64(r.key_commitment)), num(r.members.length),
      ...r.members.flatMap((m) => [text(m.user_id), field(unb64(m.identity)), text(m.role)]),
      text(r.signer.user_id), field(identityHash(r.signer)),
    ]);
  const memberListDigest = (entries) =>
    b64(sha256(canon("passauth/member-list/v1", [text(vaultId), num(entries.length), ...entries.flatMap((m) => [text(m.user_id), field(unb64(m.identity)), text(m.role)])])));
  const buildRoster = (signer, version, keyEpoch, members, raw = rawKey, entries = entriesOf(members)) => {
    const r = { format: 1, vault_id: vaultId, version, key_epoch: keyEpoch, key_commitment: commitmentOf(raw, keyEpoch), members: entries, signer: full(signer), signature: "" };
    r.signature = b64(sign(null, rosterBytes(r), edKeys[signer]));
    return { json: JSON.stringify(r), bytes: rosterBytes(r) };
  };
  const fakeDave = { user_id: full("dave").user_id, identity: b64(identityHash({ ...full("carol"), user_id: full("dave").user_id })), role: "write" };
  const rosterInputs = [
    // [name, signer, previous, version, key epoch, members, rogue]
    ["v1", "alice", null, 1, 0, [["alice", "owner"], ["bob", "write"], ["carol", "read", true]]],
    ["v2", "alice", "v1", 2, 0, [["alice", "owner"], ["bob", "admin"], ["carol", "read", true]]],
    ["v3", "bob", "v2", 3, 1, [["alice", "owner"], ["bob", "admin"]]],
    // Bob (an admin) adds Dave; Carol's app has a signing key now, but Bob keeps her legacy listing.
    ["v3-dave", "bob", "v2", 3, 0, [["alice", "owner"], ["bob", "admin"], ["carol", "read", false, true], ["dave", "write"]]],
    // The owner replaces it with her full identity.
    ["v4-upgrade", "alice", "v3-dave", 4, 0, [["alice", "owner"], ["bob", "admin"], ["carol", "read"], ["dave", "write"]]],
    ["v2-by-bob", "bob", null, 2, 0, [["alice", "owner"], ["bob", "admin"], ["carol", "read", true]], true],
    ["v2-other", "alice", null, 2, 0, [["alice", "owner"], ["bob", "admin"]], true],
    ["v4-new-owner", "bob", null, 4, 1, [["bob", "owner"]], true],
    ["v4-older-epoch", "bob", null, 4, 0, [["alice", "owner"], ["bob", "admin"]], true],
    ["v4-bob-adds-admin", "bob", null, 4, 1, [["alice", "owner"], ["bob", "admin"], ["carol", "admin"]], true],
    ["v4-bob-swaps-dave", "bob", null, 4, 0, [["alice", "owner"], ["bob", "admin"], ["carol", "read", true], "fake-dave"], true],
    ["v4-new-key-same-epoch", "bob", null, 4, 1, [["alice", "owner"], ["bob", "admin"]], true, rawKey2],
  ];
  const rosters = {};
  const rosterHashes = {};
  const rosterCases = rosterInputs.map(([name, signer, previous, version, keyEpoch, members, rogue, raw]) => {
    const entries = members.map((m) => (m === "fake-dave" ? null : m));
    let built = buildRoster(signer, version, keyEpoch, entries.filter(Boolean), raw ?? rawKey);
    if (members.includes("fake-dave")) {
      const list = [...entriesOf(entries.filter(Boolean)), fakeDave].sort((x, y) => Buffer.compare(Buffer.from(x.user_id), Buffer.from(y.user_id)));
      built = buildRoster(signer, version, keyEpoch, null, raw ?? rawKey, list);
    }
    const r = JSON.parse(built.json);
    must(ed25519Verify(r.signer.signing_key, built.bytes, r.signature), `roster ${name} doesn't verify independently`);
    if (!rogue) {
      const inputs = members.map(([n, role, inLegacy]) => ({ ...who(n, inLegacy), role }));
      const review = core.rosterReview(vaultId, previous ? rosters[previous] : null, full(signer), inputs, null);
      must(review.digest === memberListDigest(r.members) && review.version === version, `roster ${name}'s review differs`);
      const json = signers[signer].signRoster(vaultKey, vaultId, previous ? rosters[previous] : null, keyEpoch, inputs, review.digest);
      must(json === built.json, `roster ${name} differs from the one built here`);
      must(vaultKey.matchesRoster(vaultId, json) && !vaultKey.matchesRoster(`${vaultId}0`, json), "the vault key doesn't match its roster");
    }
    rosters[name] = built.json;
    // The roster's hash: SHA-256 of ["passauth/member-roster-hash/v1", signed bytes, signature].
    const hash = b64(sha256(canon("passauth/member-roster-hash/v1", [field(built.bytes), field(unb64(r.signature))])));
    must(core.rosterHash(built.json) === hash, `roster ${name}'s hash differs`);
    rosterHashes[name] = hash;
    return { name, signer, previous, version, keyEpoch, members, rogue: !!rogue, json: built.json, signedBytes: built.bytes.toString("hex"), hash };
  });
  // The core refuses to sign what it would refuse to accept.
  for (const [name, signer, previous, members] of [
    ["admin adds an admin", "bob", "v3", [["alice", "owner"], ["bob", "admin"], ["carol", "admin"]]],
    ["writer signs", "carol", "v1", [["alice", "owner"], ["bob", "write"], ["carol", "admin"]]],
  ]) {
    const inputs = members.map(([n, role]) => ({ ...full(n), role }));
    must(outcome(() => core.rosterReview(vaultId, rosters[previous], full(signer), inputs, null)).error === "roster_unauthorized", `the core reviewed: ${name}`);
  }

  const nameOf = (json) => Object.keys(rosters).find((k) => rosters[k] === json) ?? json;
  const chainInputs = [
    // [trusted, newer, latest (default: the last of newer, else trusted), vault]
    [null, ["v1", "v2", "v3"]],
    ["v1", ["v2", "v3"]],
    ["v3", []],
    [null, ["v2"]],
    ["v1", ["v3"]],
    ["v2", ["v1"]],
    ["v1", ["v2-by-bob"]],
    ["v2", ["v3", "v4-new-owner"]],
    ["v2", ["v3", "v4-older-epoch"]],
    [null, [], "v1"],
    ["v2", ["v3-dave", "v4-upgrade"]],
    ["v3", ["v4-bob-adds-admin"]],
    ["v3-dave", ["v4-bob-swaps-dave"]],
    ["v3", ["v4-new-key-same-epoch"]],
    ["v1", ["v2"], "v3"],
    ["v2", ["v3"], "v3-dave"],
    [null, ["v1", "v2"], "v2-other"],
    [null, ["v1"], "v1", "00000000-0000-4000-8000-0000000000f2"],
  ];
  const chainCases = chainInputs.map(([trusted, newer, latest, vault]) => {
    const last = latest ?? newer.at(-1) ?? trusted;
    const r = outcome(() => nameOf(core.verifyRosterChain(vault ?? vaultId, trusted ? rosters[trusted] : null, newer.map((n) => rosters[n]), rosters[last])));
    return { vault: vault ?? vaultId, trusted, newer, latest: last, ...r };
  });
  const headInputs = [[null, null], [null, "v2"], ["v1", "v3"], ["v2", "v2"], ["v2", "v1"], ["v2", null], ["v2", "v2-other"], ["v2", "v3", "00000000-0000-4000-8000-0000000000f2"]];
  const headCases = headInputs.map(([remembered, latest, vault]) => ({
    vault: vault ?? vaultId,
    remembered,
    latest,
    ...outcome(() => core.rosterHead(vault ?? vaultId, remembered ? rosters[remembered] : null, latest ? rosters[latest] : null)),
  }));

  // Server member lists against roster v2.
  const memberInputs = (members) => members.map(([name, role, isLegacy]) => ({ ...who(name, isLegacy), role }));
  const diffInputs = [
    [["alice", "owner"], ["bob", "admin"], ["carol", "read", true]],
    [["alice", "owner"], ["bob", "admin"], ["carol", "read"]],
    [["alice", "owner"], ["bob", "admin", true], ["carol", "write", true]],
    [["alice", "owner"], ["bob", "admin"]],
  ];
  const memberDiffCases = diffInputs.map((members) => ({ roster: "v2", members, expected: core.compareMembers(rosters.v2, memberInputs(members)) }));
  const roleIds = [["alice", false], ["bob", false], ["bob", true], ["carol", true], ["carol", false]];
  const roleCases = ["v2", "v3-dave", "v4-upgrade"].flatMap((roster) =>
    roleIds.map(([name, isLegacy]) => ({
      roster,
      identity: [name, isLegacy],
      member: core.rosterMemberRole(rosters[roster], who(name, isLegacy)) ?? null,
      signer: core.rosterSignerRole(rosters[roster], who(name, isLegacy)) ?? null,
    })),
  );

  // Key pins: Bob pinned with his signing identity, Carol as legacy (time 1000).
  let pins = core.pinSet(null, full("bob"), "bob@example.com", true, 1000);
  pins = core.pinSet(pins, legacy("carol"), "carol@example.com", false, 1000);
  const pinCheckCases = [
    ["alice", false, null],
    ["bob", false, null],
    ["bob", true, null],
    ["carol", true, null],
    ["carol", false, "carol@example.com"],
    ["dave", false, "dave@example.com"],
    ["dave", false, " Bob@Example.COM"],
    ["dave", false, "ＢＯＢ@example.com"],
    ["dave", false, "bob@ｅｘａｍｐｌｅ.com"],
  ].map(([name, isLegacy, email]) => ({ identity: [name, isLegacy], email, expected: core.pinCheck(pins, who(name, isLegacy), email) }));
  // Emails as pins compare them: trimmed, NFKC, lower case, IDNA ASCII domain. Checked here with
  // String.prototype.normalize and node:url's domainToASCII (UTS #46), independently of the core.
  const normalizeEmail = (e) => {
    const l = e.trim().normalize("NFKC").toLowerCase().normalize("NFKC").trim();
    const at = l.lastIndexOf("@");
    if (at < 0 || at === l.length - 1) return l;
    const ascii = domainToASCII(l.slice(at + 1));
    return ascii ? `${l.slice(0, at + 1)}${ascii}` : l;
  };
  const emailCases = [" Bob@Example.COM ", "ＢＯＢ@ｅｘａｍｐｌｅ.com", "erin@Bücher.example", "erin@xn--bcher-kva.example", "ﬁona@EXAMPLE.org", "no-at-sign", "x@"].map((email) => {
    const expected = core.normalizeEmail(email);
    must(expected === normalizeEmail(email), `email ${email} normalized differently`);
    return { email, expected };
  });

  // A signer with Bob's id but Carol's keys can't even verify (the identity signatures bind the id).
  const forged = { ...full("carol"), user_id: full("bob").user_id };
  must(outcome(() => core.pinCheck(pins, forged, null)).error === "bad_signature", "a forged identity was checked against the pins");

  // Reviews (with Alice's pins above; emails as the server lists them).
  const reviewInputs = [
    ["first", null, "alice", [["alice", "owner"], ["bob", "write", false, "bob@new.example"], ["carol", "read", true, "carol@example.com"]]],
    ["role change", "v1", "alice", [["alice", "owner"], ["bob", "admin", false, "bob@example.com"], ["carol", "read", true]]],
    ["email conflict", "v2", "alice", [["alice", "owner"], ["bob", "admin"], ["carol", "read", true], ["dave", "write", false, "BOB@example.com"]]],
    ["admin keeps legacy", "v2", "bob", [["alice", "owner"], ["bob", "admin"], ["carol", "read"]]],
  ];
  const reviewCases = reviewInputs.map(([name, previous, signer, members]) => {
    const inputs = members.map(([n, role, isLegacy, email]) => ({ ...who(n, isLegacy), role, ...(email ? { email } : {}) }));
    const expected = core.rosterReview(vaultId, previous ? rosters[previous] : null, full(signer), inputs, pins);
    // A blocked review has no digest (nothing can be signed from it).
    const digest = expected.blocked ? "" : memberListDigest(expected.members.map((m) => ({ user_id: m.user_id, identity: m.identity, role: m.role })));
    must(expected.digest === digest, `review ${name}'s digest differs`);
    return { name, previous, signer, members, expected };
  });

  // Key epoch pins: key ids, retired keys, signed since.
  const ep = (k, keyEpoch) => k.epochPin(vaultId, keyEpoch);
  const k1 = vaultKey;
  const k2 = vaultKey2;
  must(ep(k1, 3).key_id === keyIds.first && ep(k2, 3).key_id === keyIds.second, "an epoch pin's key id differs");
  const pinned = (k, keyEpoch, retired = []) => ({ ...ep(k, keyEpoch), retired, signed_since: null });
  const epochCheckCases = [
    [null, ep(k1, 0)],
    [pinned(k1, 1), ep(k1, 1)],
    [pinned(k1, 1), ep(k2, 2)],
    [pinned(k2, 2), ep(k1, 1)],
    [pinned(k2, 2), ep(k1, 2)],
    [pinned(k1, 1), ep(k1, 2)],
    [pinned(k2, 2, [keyIds.first]), ep(k1, 3)],
  ].map(([pin, current]) => ({ pinned: pin, current, expected: core.epochCheck(pin, current) }));
  const keyPinsWithEpoch = core.pinsSetEpoch(pins, vaultId, ep(k1, 1), 2);
  must(JSON.stringify(core.pinsSetEpoch(keyPinsWithEpoch, vaultId, ep(k1, 0), 2)) === JSON.stringify(keyPinsWithEpoch), "an epoch pin was lowered");
  const pinsEpochCases = [
    [ep(k1, 0), 2],
    [ep(k1, 1), 2],
    [ep(k1, 1), null],
    [ep(k1, 1), 1],
    [ep(k2, 2), 3],
    [ep(k1, 2), 3],
  ].map(([current, rosterVersion]) => ({ current, rosterVersion, expected: core.pinsEpochCheck(keyPinsWithEpoch, vaultId, current, rosterVersion) }));
  // Retired key ids are the first 12 bytes of the key id.
  const retiredId = (id) => b64(unb64(id).subarray(0, 12));
  must(keyPinsWithEpoch.epochs[vaultId].roster_version_max === 2, "the trusted roster version wasn't pinned");
  const keyPinsRaised = core.pinsSetEpoch(keyPinsWithEpoch, vaultId, ep(k2, 2), 3);
  must(keyPinsRaised.epochs[vaultId].retired[0] === retiredId(keyIds.first), "the replaced key wasn't retired");
  must(core.epochCheck({ ...ep(k2, 2), retired: [keyIds.first] }, ep(k1, 7)) === "older", "a full retired id from before was ignored");
  const mergedEpochs = core.mergePins(keyPinsWithEpoch, core.pinsSetEpoch(null, vaultId, ep(k2, 2), null)).epochs;
  must(mergedEpochs[vaultId].key_epoch === 2 && mergedEpochs[vaultId].retired[0] === retiredId(keyIds.first), "merging didn't keep the higher epoch");
  const keyPinsLeft = core.pinsLeave(keyPinsRaised, vaultId, 3, 2000);
  must(core.pinsLeave(keyPinsRaised, vaultId, 0, 2000).left[vaultId].roster_version === 3, "a tombstone forgot the roster version its pin knew");
  // Grandfathered: only by the unlock that created the signing identity (else "trust memory
  // missing": an empty list); `createdIdentity` must be given.
  const keyPinsGrandfathered = core.pinsGrandfather(pins, [vaultId], true);
  const keyPinsWithheld = core.pinsGrandfather(pins, [vaultId], false);
  must(keyPinsWithheld.grandfathered.length === 0, "grandfathered without creating the identity");
  must(outcome(() => core.pinsGrandfather(pins, [vaultId])).error !== undefined, "grandfathering without createdIdentity didn't throw");
  // Pinned while unsigned (a grandfathered vault accepted at epoch 1), and pinned up to roster v3.
  const keyPinsUnsigned = core.pinsSetEpoch(keyPinsGrandfathered, vaultId, ep(k1, 1), null);
  const keyPinsRosterMax = core.pinsObserve(keyPinsWithEpoch, { vault_id: vaultId, key_kind: "sealed", key: ep(k1, 1), roster_version: 3, roster_hash: rosterHashes.v3, signed_share: true, paused: false }).pins;
  must(keyPinsRosterMax.epochs[vaultId].roster_hash === rosterHashes.v3, "the trusted roster's hash wasn't pinned");
  const pinSets = {
    none: null,
    withEpoch: keyPinsWithEpoch,
    raised: keyPinsRaised,
    left: keyPinsLeft,
    grandfathered: keyPinsGrandfathered,
    withheld: keyPinsWithheld,
    unsigned: keyPinsUnsigned,
    rosterMax: keyPinsRosterMax,
  };

  // Admission of vault rows: [pins, key_kind, key (k, epoch) or null, roster version, signed share,
  // paused, roster (its hash; optional)].
  const admissionInputs = [
    ["none", "account", [1, 0], null, false, false],
    ["none", "account", null, null, false, false],
    ["none", "sealed", [1, 0], 1, true, false],
    ["none", "sealed", [1, 0], null, false, false],
    ["grandfathered", "sealed", [1, 0], null, false, false],
    ["grandfathered", "sealed", [1, 0], null, true, false],
    ["grandfathered", "sealed", [1, 0], 1, false, false],
    ["withEpoch", "sealed", [1, 1], 2, true, false],
    ["withEpoch", "sealed", [2, 2], 3, true, false],
    ["withEpoch", "sealed", [1, 1], 2, false, false],
    ["withEpoch", "sealed", [1, 1], null, true, false],
    ["withEpoch", "account", [1, 1], null, false, false],
    ["withEpoch", "account", [1, 1], 2, false, false],
    ["raised", "sealed", [1, 3], 4, true, false],
    ["raised", "sealed", [2, 2], 3, true, true],
    ["raised", "account", [2, 2], 3, false, true],
    ["left", "sealed", [2, 2], 3, true, false],
    ["left", "sealed", [2, 2], 4, true, false],
    ["left", "sealed", [1, 3], 4, true, false],
    ["left", "account", [2, 2], 4, false, false],
    // Grandfathering covers unsigned rows only: a signed one needs consent.
    ["grandfathered", "sealed", [1, 0], 1, true, false, "v1"],
    // Trust memory missing (key pins withheld): nothing grandfathered.
    ["withheld", "sealed", [1, 0], null, false, false],
    // Pinned unsigned: re-signed at the same key → pin; replaced unsigned → consent.
    ["unsigned", "sealed", [1, 1], null, false, false],
    ["unsigned", "sealed", [1, 1], 2, true, false, "v2"],
    ["unsigned", "sealed", [2, 2], null, false, false],
    ["unsigned", "sealed", [2, 2], 2, true, false],
    ["unsigned", "account", [2, 2], null, false, false],
    // The highest trusted roster (v3) and its hash.
    ["rosterMax", "sealed", [1, 1], 3, true, false, "v3"],
    ["rosterMax", "sealed", [1, 1], 3, true, false, "v3-dave"],
    ["rosterMax", "sealed", [1, 1], 3, true, false],
    ["rosterMax", "sealed", [1, 1], 2, true, false, "v2"],
    ["rosterMax", "sealed", [1, 1], 4, true, false, "v4-upgrade"],
    ["rosterMax", "account", [1, 1], 3, false, false, "v3-dave"],
  ];
  const keyOf = (n) => (n === 1 ? k1 : k2);
  const observationOf = ([, kind, key, rosterVersion, signedShare, paused, roster]) => ({
    vault_id: vaultId,
    key_kind: kind,
    key: key ? ep(keyOf(key[0]), key[1]) : null,
    roster_version: rosterVersion,
    ...(roster ? { roster_hash: rosterHashes[roster] } : {}),
    signed_share: signedShare,
    paused,
  });
  const admissionCases = admissionInputs.map((input) => {
    const observation = observationOf(input);
    const expected = core.pinsAdmit(pinSets[input[0]], observation);
    const observed = core.pinsObserve(pinSets[input[0]], observation);
    must(JSON.stringify(observed.admission) === JSON.stringify(expected), "pinsObserve's verdict differs from pinsAdmit's");
    must(observed.changed === (expected.status === "ok" && expected.pin), "pinsObserve changed pins it shouldn't have (or didn't)");
    return { pins: input[0], observation, expected };
  });
  // A sync's rows observed in turn (each step's pins from the step before), from grandfathered:
  // accepted unsigned, re-signed at the same key (v2 now trusted), then the same pins on a device
  // with no memory of the vault: the roster stripped, or a server key at epoch 2 → downgraded.
  const observationSteps = [
    ["grandfathered", "sealed", [1, 1], null, false, false],
    ["", "sealed", [1, 1], 2, true, false, "v2"],
    ["", "sealed", [1, 1], 2, true, false, "v2"],
    ["", "sealed", [1, 1], null, false, false],
    ["", "sealed", [2, 2], null, false, false],
  ];
  let stepPins = pinSets.grandfathered;
  const observations = observationSteps.map((input) => {
    const observation = observationOf(input);
    const expected = core.pinsObserve(stepPins, observation);
    stepPins = expected.pins;
    return { observation, expected };
  });
  must(observations[1].expected.admission.pin && observations[1].expected.pins.epochs[vaultId].signed_since === 2, "re-signing didn't pin the vault signed");
  must(observations.slice(3).every((o) => o.expected.admission.reason === "downgraded"), "a stripped re-signed vault wasn't refused");
  const rejoined = outcome(() => core.pinsSetEpoch(keyPinsLeft, vaultId, ep(k2, 2), 4));
  must(rejoined.expected && !rejoined.expected.left[vaultId], "a re-share didn't clear the tombstone");
  must(outcome(() => core.pinsSetEpoch(keyPinsLeft, vaultId, ep(k2, 2), 3)).error === "rollback", "a tombstone was cleared without a newer roster");
  const legacyWraps = Object.entries(pinSets).map(([set, p]) => ({ pins: set, expected: core.pinsLegacyWrapAllowed(p, vaultId) }));

  // The account's own identity, remembered once.
  const own = signers.alice.identityHash();
  const withOwn = core.pinsSetOwnIdentity(pins, own);
  const ownIdentityCases = [
    ["none", own],
    ["withOwn", own],
    ["withOwn", null],
    ["withOwn", signers.bob.identityHash()],
  ].map(([set, listed]) => ({ pins: set, listed, expected: core.pinsCheckOwnIdentity(set === "withOwn" ? withOwn : null, listed) }));
  must(outcome(() => core.pinsSetOwnIdentity(withOwn, signers.bob.identityHash())).error === "identity_mismatch", "the own identity was replaced");

  vaultKey.free();
  vaultKey2.free();
  for (const s of Object.values(signers)) s.free();
  for (const a of Object.values(accounts)) a.free();

  return {
    accounts: fixtures.accounts,
    vault: fixtures.vault,
    openings,
    keyIds,
    xeddsa,
    identities,
    forgedUpgrade,
    shares,
    rosters: rosterCases,
    commitments: commitmentCases,
    chains: chainCases,
    heads: headCases,
    memberDiffs: memberDiffCases,
    rosterRoles: roleCases,
    keyPins: pins,
    pinChecks: pinCheckCases,
    reviews: reviewCases,
    epochChecks: epochCheckCases,
    keyPinsWithEpoch,
    pinsEpochChecks: pinsEpochCases,
    keyPinsRaised,
    mergedEpochs,
    keyPinsLeft,
    keyPinsGrandfathered,
    keyPinsWithheld,
    keyPinsUnsigned,
    keyPinsRosterMax,
    admissions: admissionCases,
    observations,
    emails: emailCases,
    legacyWraps,
    ownIdentity: { hash: own, pins: withOwn, checks: ownIdentityCases },
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
  const signing = contact.newSigningIdentity();
  const instances = {
    Account: contact,
    VaultKey: contact.newVaultKey("vault").takeKey(),
    EmergencyKey: emergency.takeKey(),
    LoginRequestKey: request,
    ApprovedLogin: request.open(approval.sealed, "grantor", "req"),
    FileEncryptor: new core.FileEncryptor(core.fileNewKey(), "item", "file"),
    FileDecryptor: new core.FileDecryptor(core.fileNewKey(), "item", "file"),
    // The core's KDF floor: the one slow fixture (OPAQUE functions take master keys).
    SigningIdentity: signing.takeIdentity(),
    NewSigningIdentity: signing,
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
