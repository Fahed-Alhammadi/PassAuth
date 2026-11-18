// Golden vectors for the site logic every PassAuth client uses: host names, public suffixes and
// base domains (the full Public Suffix List), website matching (`allowRegex`: false for a login in
// a vault somebody shared, whose regular expressions never count), the https→http downgrade rule,
// the regular-expression engine's refusals and warnings, the save rule, passkey "Save in" targets
// and RP ID checks. Also the phrases an approving app offers for a sign-in request
// (`loginPhraseChoices`), which must be the same on every device and in every binding, and signed
// sharing (`signedSharing`: identities and their XEdDSA cross-signatures, share signatures, member
// rosters, reviews and chains, key ids, key pins, key epoch pins and vault admission; byte-exact,
// cross-checked here independently of the core with node:crypto and BigInt arithmetic), the item
// edit counter rule (`itemRev`), Send v2's password-derived content key (`sendV2`, cross-checked
// with node:crypto's Argon2id and HKDF) and vault manifests (`vaultManifest`: item terms, sums,
// sealed manifests, their links and chains (forks, key replacement, baseline, pruned logs, logs
// with rubbish in them), every verdict of the check and of "Use the server's copy", cross-checked with node:crypto's HKDF, HMAC and SHA-256, BigInt sums
// and ChaCha20-Poly1305).
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
import { argon2Sync, createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, sign, verify } from "node:crypto";
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
    itemRev: itemRevVectors(core),
    sendV2: sendV2Vectors(core),
    vaultManifest: vaultManifestVectors(core),
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
    // (no epoch; what the apps write while some app of the account reads only v1), the same key as an epoch-bound v2 wrap at epoch 0
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
  // v1 while `/sync` says some app of the account reads only that…
  must(xopen(aliceKey, vaultKey.wrapFor(accounts.alice, vaultId), `passauth/vault-key/v1/${vaultId}`).equals(rawKey), "wrapFor doesn't write a v1 wrap");
  // …and v2 when `/sync` says every app reads it: bound to the epoch given (the one after the write).
  const boundWrap = vaultKey.wrapForBound(accounts.alice, vaultId, 7);
  must(xopen(aliceKey, boundWrap, `passauth/vault-key/v2/${vaultId}/7`, true).equals(rawKey), "wrapForBound doesn't write a v2 wrap at its epoch");
  const fresh = accounts.alice.newVaultKeyBound(vaultId, 0);
  must(core.accountWrapIsBound(fresh.wrapped) && xopen(aliceKey, fresh.wrapped, `passauth/vault-key/v2/${vaultId}/0`, true).length === 32, "newVaultKeyBound doesn't write a v2 wrap at epoch 0");
  fresh.free();
  must(core.accountWrapIsBound(fixtures.vault.wrappedKeyV2) && !core.accountWrapIsBound(fixtures.vault.wrappedKey) && !core.accountWrapIsBound("!"), "accountWrapIsBound differs");
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
  // What a review shows, bound to the version, "first" and the previous roster's hash (an empty
  // field without one): ["passauth/member-list/v2", vault id, version, first (1/0), previous
  // roster hash, count, members…].
  const memberListDigest = (entries, previous) => {
    const prev = previous ? JSON.parse(rosters[previous]) : null;
    return b64(
      sha256(
        canon("passauth/member-list/v2", [
          text(vaultId),
          num(prev ? prev.version + 1 : 1),
          num(prev ? 0 : 1),
          field(prev ? unb64(rosterHashes[previous]) : Buffer.alloc(0)),
          num(entries.length),
          ...entries.flatMap((m) => [text(m.user_id), field(unb64(m.identity)), text(m.role)]),
        ]),
      ),
    );
  };
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
      must(review.digest === memberListDigest(r.members, previous) && review.version === version, `roster ${name}'s review differs`);
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
  // Emails as pins compare them: invisible characters removed (Cf, Cc, Zl, Zp and every
  // Default_Ignorable_Code_Point — round 5: also U+034F, variation selectors, the Hangul fillers;
  // JavaScript's trim would strip U+FEFF but not U+200B, so they are removed explicitly here and
  // in the core), NFKC, lower case, NFKC, removed again, trimmed; the domain without trailing dots
  // in IDNA ASCII, again without trailing dots (IDNA maps U+3002 and U+FF61 to "."); when there is
  // no domain or IDNA refuses it, the address as it is if ASCII, else with non-ASCII characters
  // (and "\") written as \u{hex} (so normalizing twice gives the same). Checked here with
  // String.prototype.normalize, Unicode property escapes and node:url's domainToASCII (UTS #46 as
  // the URL Standard), independently of the core.
  const INVISIBLE = /[\p{Cf}\p{Cc}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
  const stripInvisible = (s) => s.replace(INVISIBLE, "");
  const FORBIDDEN_DOMAIN = /[\x00-\x20#%/:<>?@[\\\]^|\x7f]/;
  const escapeNonAscii = (s) => Array.from(s, (c) => (c.codePointAt(0) < 0x80 && c !== "\\" ? c : `\\u{${c.codePointAt(0).toString(16)}}`)).join("");
  const normalizeEmail = (e) => {
    const l = stripInvisible(stripInvisible(e).normalize("NFKC").toLowerCase().normalize("NFKC")).trim();
    const at = l.lastIndexOf("@");
    const domain = at < 0 ? "" : l.slice(at + 1).replace(/\.+$/, "");
    // node's domainToASCII parses a whole host, so "\\" or "/" would end it early: forbidden domain
    // code points are refused here first, as the core's IDNA (URL deny list) does.
    const ascii = domain && !FORBIDDEN_DOMAIN.test(domain) ? domainToASCII(domain).replace(/\.+$/, "") : "";
    if (ascii) return `${l.slice(0, at + 1)}${ascii}`;
    return /^[\x00-\x7f]*$/.test(l) ? l : escapeNonAscii(l);
  };
  const emailCases = [
    " Bob@Example.COM ",
    "ＢＯＢ@ｅｘａｍｐｌｅ.com",
    "erin@Bücher.example",
    "erin@xn--bcher-kva.example",
    "ﬁona@EXAMPLE.org",
    "no-at-sign",
    "x@",
    // Review round 4 M3: invisible characters, a byte order mark, a trailing dot, a tag
    // character after a look-alike domain, a Hangul filler, a refused domain, a backslash.
    "ali\u200Bce@example.com",
    "\uFEFFalice@example.com",
    "alice@example.com.",
    "alice@example.com\u200B",
    "alice@ex\u0430mple.com\u{E0001}",
    "al\u202Eice@exam\u3164ple.com",
    "alice\u2028@example.com",
    "al\u0456ce@b\u00FC cher.example",
    "a\\b@",
    "x@.",
    // Review round 5 M: default-ignorable characters in the local part, an ideographic full stop
    // (and its halfwidth form) after the domain, an escaped address normalized again.
    "alice\u034F@example.com",
    "ali\uFE0Fce@example.com",
    "alice\u{E0100}@example.com",
    "ali\u180Bce@example.com",
    "ali\u17B4ce@example.com",
    "alice@example.com\u3002",
    "alice@example.com\uFF61",
    "al\\u{456}ce@b\\u{fc} cher.example",
  ].map((email) => {
    const expected = core.normalizeEmail(email);
    must(expected === normalizeEmail(email), `email ${email} normalized differently`);
    must(core.normalizeEmail(expected) === expected, `email ${email} normalized twice differs`);
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
    const digest = expected.blocked ? "" : memberListDigest(expected.members.map((m) => ({ user_id: m.user_id, identity: m.identity, role: m.role })), previous);
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
  // Pinning a key this device gave the vault itself (`pinsRecordRotation`, round 5: a roster
  // version always with its hash; `pinsSetEpoch` is gone). Recorded here as the account's sealed
  // row (an `account` row would mark the vault `own`).
  const record = (p, current, rosterVersion = null, roster = null) =>
    core.pinsRecordRotation(p, vaultId, "sealed", current, rosterVersion, roster ? rosterHashes[roster] : null);
  const keyPinsWithEpoch = record(pins, ep(k1, 1), 2, "v2");
  must(outcome(() => record(keyPinsWithEpoch, ep(k1, 0), 2, "v2")).error === "rollback", "an epoch pin was lowered");
  must(outcome(() => record(keyPinsWithEpoch, ep(k2, 2), 3)).error !== undefined, "a roster version was pinned without its hash");
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
  must(keyPinsWithEpoch.epochs[vaultId].roster_version_max === 2 && keyPinsWithEpoch.epochs[vaultId].roster_hash === rosterHashes.v2, "the trusted roster wasn't pinned with its hash");
  const keyPinsRaised = record(keyPinsWithEpoch, ep(k2, 2), 3, "v3");
  must(keyPinsRaised.epochs[vaultId].retired[0] === retiredId(keyIds.first), "the replaced key wasn't retired");
  must(core.epochCheck({ ...ep(k2, 2), retired: [keyIds.first] }, ep(k1, 7)) === "older", "a full retired id from before was ignored");
  const mergedEpochs = core.mergePins(keyPinsWithEpoch, record(null, ep(k2, 2))).epochs;
  must(mergedEpochs[vaultId].key_epoch === 2 && mergedEpochs[vaultId].retired[0] === retiredId(keyIds.first), "merging didn't keep the higher epoch");
  const keyPinsLeft = core.pinsLeave(keyPinsRaised, vaultId, 3, 2000);
  must(core.pinsLeave(keyPinsRaised, vaultId, 0, 2000).left[vaultId].roster_version === 3, "a tombstone forgot the roster version its pin knew");
  // Grandfathered: only by the unlock that created the signing identity (else "trust memory
  // missing": an empty list); `createdIdentity` must be given; each vault with the key it has now.
  const candidates = [{ vault_id: vaultId, key_id: keyIds.first }];
  const keyPinsGrandfathered = core.pinsGrandfather(pins, candidates, true);
  const keyPinsWithheld = core.pinsGrandfather(pins, candidates, false);
  must(Object.keys(keyPinsWithheld.grandfathered).length === 0, "grandfathered without creating the identity");
  must(keyPinsGrandfathered.grandfathered[vaultId] === keyIds.first, "a grandfathered vault lost its key id");
  must(outcome(() => core.pinsGrandfather(pins, candidates)).error !== undefined, "grandfathering without createdIdentity didn't throw");
  must(outcome(() => core.pinsGrandfather(pins, [vaultId], true)).error !== undefined, "grandfathering took a vault id without its key id");
  // Pinned while unsigned (a grandfathered vault accepted at epoch 1), and pinned up to roster v3.
  const keyPinsUnsigned = record(keyPinsGrandfathered, ep(k1, 1));
  const keyPinsRosterMax = core.pinsObserve(keyPinsWithEpoch, { vault_id: vaultId, key_kind: "sealed", key: ep(k1, 1), roster_version: 3, roster_hash: rosterHashes.v3, signed_share: true, paused: false }).pins;
  must(keyPinsRosterMax.epochs[vaultId].roster_hash === rosterHashes.v3, "the trusted roster's hash wasn't pinned");
  // The account's own vault (pinned from an `account` row: marked `own`).
  const keyPinsOwn = core.pinsObserve(null, { vault_id: vaultId, key_kind: "account", key: ep(k1, 1), roster_version: null, signed_share: false, paused: false }).pins;
  must(keyPinsOwn.epochs[vaultId].own === true, "an own vault wasn't marked");
  // The same own vault, its key at epoch 1 seen in a v2 (epoch-bound) account wrap: v1 refused at 0 and 1.
  const keyPinsBound = core.pinsObserve(keyPinsOwn, { vault_id: vaultId, key_kind: "account", key: ep(k1, 1), roster_version: null, signed_share: false, paused: false, bound_wrap: true }).pins;
  must(keyPinsBound.epochs[vaultId].bound_since === 1, "a v2 wrap's epoch wasn't recorded");
  const pinSets = {
    none: null,
    withEpoch: keyPinsWithEpoch,
    raised: keyPinsRaised,
    left: keyPinsLeft,
    grandfathered: keyPinsGrandfathered,
    withheld: keyPinsWithheld,
    unsigned: keyPinsUnsigned,
    rosterMax: keyPinsRosterMax,
    own: keyPinsOwn,
  };

  // Admission of vault rows: [pins, key_kind, key (k, epoch) or null, roster version, signed share,
  // paused, roster (its hash; default: the roster of that version), chain, invitation].
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
    // Grandfathered with its key only (round 5): another key under that id needs consent.
    ["grandfathered", "sealed", [2, 0], null, false, false],
    // Trust memory missing (key pins withheld): nothing grandfathered.
    ["withheld", "sealed", [1, 0], null, false, false],
    // Pinned unsigned: re-signed at the same key → consent `first_signed` (round 5 M: the first
    // signer is never pinned silently); replaced unsigned → consent.
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
    // Review round 4 (puppet signer): a new key on a vault never seen signed needs consent even
    // when signed (its roster may start at a version 1 a server-made account signed); the own
    // vault served as sealed with a new key: consent with `own`; at the same key, signed: consent
    // with `own` and `first_signed` (round 5).
    ["grandfathered", "sealed", [2, 2], 1, true, false, "v1"],
    ["own", "account", [1, 1], null, false, false],
    ["own", "sealed", [2, 2], 1, true, false, "v1"],
    ["own", "sealed", [2, 2], null, false, false],
    ["own", "sealed", [1, 1], 1, true, false, "v1"],
    ["withEpoch", "account", [1, 1], 2, false, false, "v2"],
    // A chain fetched from version 1 must contain the roster the pins remember at their highest
    // version (v3) with its hash: another roster there (v3-dave, as a chain re-signed by a
    // server-made account would have) → roster_forked; the real one, or a chain from a
    // remembered roster after it → ok.
    ["rosterMax", "sealed", [1, 1], 4, true, false, "v4-upgrade", [[1, "v1"], [2, "v2"], [3, "v3-dave"], [4, "v4-upgrade"]]],
    ["rosterMax", "sealed", [1, 1], 4, true, false, "v4-upgrade", [[1, "v1"], [2, "v2"], [3, "v3"], [4, "v4-upgrade"]]],
    ["rosterMax", "sealed", [1, 1], 4, true, false, "v4-upgrade", [[4, "v4-upgrade"]]],
    // Invitations (round 5): a fresh one (declinable); an unsigned one on a grandfathered id is
    // never grandfathered; the account's own vault → own_vault; a held vault: the same key → held,
    // a newer signed key on a vault with signed history → consent `held`, on one without → held;
    // a left vault → the re-join consent as for rows.
    ["none", "sealed", [1, 1], 2, true, false, "v2", null, true],
    ["grandfathered", "sealed", [1, 0], null, false, false, null, null, true],
    ["own", "sealed", [2, 2], 2, true, false, "v2", null, true],
    ["withEpoch", "sealed", [1, 1], 2, true, false, "v2", null, true],
    ["withEpoch", "sealed", [2, 2], 3, true, false, "v3", null, true],
    ["unsigned", "sealed", [2, 2], 2, true, false, "v2", null, true],
    ["left", "sealed", [2, 2], 4, true, false, "v4-upgrade", null, true],
  ];
  const keyOf = (n) => (n === 1 ? k1 : k2);
  // Every roster version comes with its roster's hash (round 5 H).
  const rosterOfVersion = { 1: "v1", 2: "v2", 3: "v3", 4: "v4-upgrade" };
  const observationOf = ([, kind, key, rosterVersion, signedShare, paused, roster, chain, invitation]) => ({
    vault_id: vaultId,
    key_kind: kind,
    key: key ? ep(keyOf(key[0]), key[1]) : null,
    roster_version: rosterVersion,
    ...(rosterVersion !== null ? { roster_hash: rosterHashes[roster ?? rosterOfVersion[rosterVersion]] } : {}),
    // The rosters verified this time ([version, roster name]…): `chain_hashes`.
    ...(chain ? { chain_hashes: Object.fromEntries(chain.map(([v, n]) => [String(v), rosterHashes[n]])) } : {}),
    signed_share: signedShare,
    paused,
    ...(invitation ? { invitation: true } : {}),
  });
  must(outcome(() => core.pinsAdmit(null, { ...observationOf(["", "sealed", [1, 1], 2, true, false]), roster_hash: null })).error !== undefined, "a roster version without its hash was admitted");
  must(outcome(() => core.pinsAdmit(null, { ...observationOf(["", "sealed", [1, 1], 2, true, false]), chain_hash: {} })).error !== undefined, "an unknown observation field was ignored");
  const admissionCases = admissionInputs.map((input) => {
    const observation = observationOf(input);
    const expected = core.pinsAdmit(pinSets[input[0]], observation);
    const observed = core.pinsObserve(pinSets[input[0]], observation);
    must(JSON.stringify(observed.admission) === JSON.stringify(expected), "pinsObserve's verdict differs from pinsAdmit's");
    must(observed.changed === (expected.status === "ok" && expected.pin), "pinsObserve changed pins it shouldn't have (or didn't)");
    if (expected.status === "consent") {
      const plain = !(expected.rejoin || expected.replaced || expected.own || expected.first_signed || expected.held);
      must(expected.declinable === (plain && (observation.signed_share || !!observation.invitation)), "declinable differs from the rule");
    }
    return { pins: input[0], observation, expected };
  });
  const verdict = (pinsName, ...rest) => admissionCases.find((c) => c.pins === pinsName && JSON.stringify(c.observation) === JSON.stringify(observationOf([pinsName, ...rest]))).expected;
  must(verdict("unsigned", "sealed", [1, 1], 2, true, false, "v2").first_signed === true, "a first signature at the same key was used silently");
  must(verdict("own", "sealed", [1, 1], 1, true, false, "v1").own === true, "the own vault signed by someone else was used silently");
  must(verdict("grandfathered", "sealed", [2, 0], null, false, false).status === "consent", "a grandfathered id with another key was used");
  must(verdict("own", "sealed", [2, 2], 2, true, false, "v2", null, true).reason === "own_vault", "an invitation took back an own vault");
  must(verdict("withEpoch", "sealed", [1, 1], 2, true, false, "v2", null, true).reason === "held", "an invitation re-offered a held key");
  must(verdict("withEpoch", "sealed", [2, 2], 3, true, false, "v3", null, true).held === true, "a newer signed key for a held vault wasn't marked held");
  must(verdict("unsigned", "sealed", [2, 2], 2, true, false, "v2", null, true).reason === "held", "an invitation replaced the key of a vault without signed history");
  // A sync's rows observed in turn (each step's pins from the step before; `accept`: the user
  // accepted that step's consent), from grandfathered: accepted unsigned, re-signed at the same key
  // (consent `first_signed`, accepted: v2 now trusted), then the same pins on a device with no
  // memory of the vault: the roster stripped, or a server key at epoch 2 → downgraded.
  const observationSteps = [
    [["grandfathered", "sealed", [1, 1], null, false, false]],
    [["", "sealed", [1, 1], 2, true, false, "v2"], true],
    [["", "sealed", [1, 1], 2, true, false, "v2"]],
    [["", "sealed", [1, 1], null, false, false]],
    [["", "sealed", [2, 2], null, false, false]],
  ];
  let stepPins = pinSets.grandfathered;
  const observations = observationSteps.map(([input, accept]) => {
    const observation = observationOf(input);
    const expected = core.pinsObserve(stepPins, observation);
    stepPins = accept ? core.pinsAccept(stepPins, observation) : expected.pins;
    return { observation, expected, ...(accept ? { accept: true, accepted: stepPins } : {}) };
  });
  must(observations[1].expected.admission.first_signed && !observations[1].expected.changed && observations[1].accepted.epochs[vaultId].signed_since === 2, "re-signing didn't need consent or wasn't pinned signed when accepted");
  must(observations.slice(3).every((o) => o.expected.admission.reason === "downgraded"), "a stripped re-signed vault wasn't refused");
  const rejoined = outcome(() => record(keyPinsLeft, ep(k2, 2), 4, "v4-upgrade"));
  must(rejoined.expected && !rejoined.expected.left[vaultId] && rejoined.expected.epochs[vaultId].rejoined_over === 2000, "a re-share didn't clear the tombstone");
  must(outcome(() => record(keyPinsLeft, ep(k2, 2), 3, "v3")).error === "rollback", "a tombstone was cleared without a newer roster");
  must(admissionCases.find((c) => c.pins === "unsigned" && c.observation.signed_share && c.observation.key.key_epoch === 2 && !c.observation.invitation).expected.replaced === true, "a signed new key on a vault never seen signed was used");

  // Accepting a consent or invitation (`pinsAccept`): the row is checked, its roster version and
  // hash remembered; refusals throw.
  const acceptInputs = [
    ["none", ["", "sealed", [1, 1], 2, true, false, "v2"]],
    ["left", ["", "sealed", [2, 2], 4, true, false, "v4-upgrade"]],
    ["left", ["", "sealed", [2, 2], 3, true, false, "v3"]],
    ["rosterMax", ["", "sealed", [1, 1], 3, true, false, "v3-dave"]],
    ["unsigned", ["", "sealed", [2, 2], 2, true, false, "v2"]],
    ["own", ["", "sealed", [2, 2], 1, true, false, "v1"]],
    ["rosterMax", ["", "sealed", [1, 1], 4, true, false, "v4-upgrade", [[1, "v1"], [2, "v2"], [3, "v3-dave"], [4, "v4-upgrade"]]]],
    // Invitations: an own vault and a held key are refused; a newer signed key is accepted.
    ["own", ["", "sealed", [2, 2], 2, true, false, "v2", null, true]],
    ["withEpoch", ["", "sealed", [1, 1], 2, true, false, "v2", null, true]],
    ["withEpoch", ["", "sealed", [2, 2], 3, true, false, "v3", null, true]],
  ];
  const acceptCases = acceptInputs.map(([set, input]) => ({ pins: set, observation: observationOf(input), ...outcome(() => core.pinsAccept(pinSets[set], observationOf(input))) }));
  must(acceptCases[0].expected.epochs[vaultId].roster_hash === rosterHashes.v2, "pinsAccept didn't remember the roster hash");
  must(acceptCases[1].expected.epochs[vaultId].rejoined_at === 4 && acceptCases[1].expected.epochs[vaultId].rejoined_over === 2000 && !acceptCases[1].expected.left[vaultId], "a re-join wasn't marked");
  must(acceptCases[2].error === "rollback" && acceptCases[3].error === "roster_forked" && acceptCases[6].error === "roster_forked", "pinsAccept accepted a refused row");
  must(acceptCases[7].error === "rollback" && acceptCases[8].error === "rollback" && acceptCases[9].expected.epochs[vaultId].key_epoch === 2, "pinsAccept took an invitation it shouldn't have (or refused one)");
  must(admissionCases.find((c) => c.observation.chain_hashes && c.observation.chain_hashes["3"] === rosterHashes["v3-dave"]).expected.reason === "roster_forked", "a chain without the pinned roster was accepted");

  // Merging key pins (review round 4): retired keys never come back, tombstones beat stale pins
  // and keep what they knew. Made-up ids: [n; 32] keys, [n; 12] retired ids; a roster version
  // always with a hash ([100 + version; 32]).
  const fakeId = (n, len = 32) => b64(Buffer.alloc(len, n));
  const fakePin = (epoch, id, retired = [], roster = null) => ({
    key_epoch: epoch,
    key_id: fakeId(id),
    retired: retired.map((r) => fakeId(r, 12)),
    signed_since: roster,
    ...(roster === null ? {} : { roster_version_max: roster, roster_hash: fakeId(100 + roster) }),
  });
  const pinsOf = (p) => ({ version: 0, pins: [], epochs: { [vaultId]: p } });
  const leftOf = (p, version, at) => core.pinsLeave(pinsOf(p), vaultId, version, at);
  const leftAt3 = leftOf(fakePin(1, 1, [], 3), 3, 10);
  const rejoinOf = (p, current, version) => core.pinsAccept(p, { vault_id: vaultId, key_kind: "sealed", key: current, roster_version: version, roster_hash: fakeId(100 + version), signed_share: true, paused: false });
  const rejoinedAt4 = rejoinOf(leftAt3, fakePin(2, 2), 4);
  const withOwnIdentity = (p, hash) => ({ ...p, own_identity: hash });
  const mergeInputs = [
    ["same epoch, the other side retired the key", pinsOf(fakePin(3, 2, [1])), pinsOf(fakePin(3, 3, [1, 2]))],
    ["same epoch, reversed", pinsOf(fakePin(3, 3, [1, 2])), pinsOf(fakePin(3, 2, [1]))],
    ["a retired key relabelled higher", pinsOf(fakePin(4, 2, [1])), pinsOf(fakePin(3, 3, [1, 2]))],
    ["a retired key relabelled higher, reversed", pinsOf(fakePin(3, 3, [1, 2])), pinsOf(fakePin(4, 2, [1]))],
    ["a fork at the same epoch", pinsOf(fakePin(3, 2, [1])), pinsOf(fakePin(3, 3, [1]))],
    ["both keys retired by the other side", pinsOf(fakePin(3, 2, [3])), pinsOf(fakePin(4, 3, [2]))],
    ["a stale pin and a leave", pinsOf(fakePin(1, 1, [], 1)), leftOf(fakePin(1, 1), 0, 100)],
    ["a tombstone keeps the newer key", pinsOf(fakePin(2, 2, [1], 1)), leftOf(fakePin(1, 1, [], 1), 1, 100)],
    ["a re-join beats its tombstone", leftAt3, rejoinedAt4],
    ["two tombstones", leftOf(fakePin(2, 2, [1], 2), 2, 50), leftOf(fakePin(3, 3, [], 5), 0, 40)],
    // Round 5 L: a later leave from a device that never saw the re-join wins over it.
    ["a later leave beats an unseen re-join", rejoinedAt4, leftOf(fakePin(1, 1, [], 3), 3, 20)],
    // Lead (round 5): another own identity → identity_mismatch, nothing merged.
    ["another own identity", withOwnIdentity(pinsOf(fakePin(1, 1)), fakeId(7)), withOwnIdentity(pinsOf(fakePin(2, 2)), fakeId(8))],
  ];
  const mergeCases = mergeInputs.map(([name, base, ours]) => ({ name, base, ours, ...outcome(() => core.mergePins(base, ours)) }));
  const merged = Object.fromEntries(mergeCases.map((c) => [c.name, c.expected]));
  for (const name of ["same epoch, the other side retired the key", "same epoch, reversed", "a retired key relabelled higher", "a retired key relabelled higher, reversed"]) {
    const p = merged[name].epochs[vaultId];
    must(p.key_id === fakeId(3) && p.retired.includes(fakeId(2, 12)), `merge "${name}" un-retired a key`);
  }
  must(merged["a fork at the same epoch"].epochs[vaultId].key_id === fakeId(2), "a fork didn't keep the base's key");
  must(!merged["a stale pin and a leave"].epochs[vaultId] && merged["a stale pin and a leave"].left[vaultId].roster_version === 1, "a stale pin undid a leave");
  must(merged["a tombstone keeps the newer key"].left[vaultId].pin.key_epoch === 2, "a tombstone forgot a newer key");
  must(merged["a re-join beats its tombstone"].epochs[vaultId].rejoined_at === 4 && !merged["a re-join beats its tombstone"].left[vaultId], "a re-join lost to its tombstone");
  const twoTombs = merged["two tombstones"].left[vaultId];
  must(twoTombs.roster_version === 5 && twoTombs.left_at === 50 && twoTombs.pin.key_epoch === 3, "two tombstones merged wrongly");
  const laterLeave = merged["a later leave beats an unseen re-join"];
  must(!laterLeave.epochs[vaultId] && laterLeave.left[vaultId].roster_version === 4 && laterLeave.left[vaultId].left_at === 20, "a later leave lost to a re-join it never saw");
  must(mergeCases.at(-1).error === "identity_mismatch", "pins of another own identity were merged");

  // A device's last-known pins merged into a newer server copy (`pinsMergeLastKnown`, round 5 M1):
  // the server copy wins for a person pinned with another identity (no write, no loop); what never
  // goes back (keys, tombstones) is kept from the device copy.
  const bobLegacy = who("bob", true);
  const bobFull = who("bob", false);
  const personPins = (identity, verified, at) => core.pinSet(pinsOf(fakePin(2, 2, [1], 2)), identity, "bob@example.com", verified, at);
  const serverCopy = { ...personPins(bobFull, false, 20), version: 5 };
  const lastKnownInputs = [
    ["another identity: the server's", serverCopy, personPins(bobLegacy, true, 10)],
    ["the same identity: verified, first seen", serverCopy, personPins(bobFull, true, 15)],
    ["a newer key and a tombstone from the device", serverCopy, core.pinsLeave(record(personPins(bobLegacy, false, 10), ep(k1, 3), 4, "v4-upgrade"), "vault-2", 0, 30)],
    ["another own identity", withOwnIdentity(serverCopy, fakeId(7)), withOwnIdentity(serverCopy, fakeId(8))],
  ];
  const lastKnownCases = lastKnownInputs.map(([name, base, lastKnown]) => ({ name, base, lastKnown, ...outcome(() => core.pinsMergeLastKnown(base, lastKnown)) }));
  must(JSON.stringify(lastKnownCases[0].expected) === JSON.stringify(serverCopy), "a last-known person pin replaced the server's (a merge loop)");
  must(lastKnownCases[1].expected.pins[0].verified && lastKnownCases[1].expected.pins[0].first_seen === 15, "a last-known copy lost verified or first seen");
  must(JSON.stringify(lastKnownCases[2].expected.pins) === JSON.stringify(serverCopy.pins) && lastKnownCases[2].expected.epochs[vaultId].key_epoch === 3 && lastKnownCases[2].expected.left["vault-2"], "a last-known copy lost keys or tombstones");
  must(lastKnownCases[3].error === "identity_mismatch", "a last-known copy of another own identity was merged");

  // Declining (`pinsDecline`, round 5 M2): never for a vault the account holds, a current row, or
  // one it left; else a tombstone at roster version 0.
  const declineInputs = [
    ["withEpoch", vaultId, false],
    ["none", vaultId, true],
    ["left", vaultId, false],
    ["none", vaultId, false],
    ["withEpoch", "vault-2", false],
  ];
  const declineCases = declineInputs.map(([set, id, currentRow]) => ({ pins: set, vaultId: id, currentRow, expected: core.pinsDecline(pinSets[set], id, currentRow, 3000) }));
  must(JSON.stringify(declineCases[0].expected) === JSON.stringify(keyPinsWithEpoch) && Object.keys(declineCases[1].expected.left ?? {}).length === 0 && declineCases[3].expected.left[vaultId].roster_version === 0, "a decline gave up a held vault or used a roster version");

  const legacyWraps = [...Object.entries(pinSets), ["bound", keyPinsBound]].flatMap(([set, p]) =>
    [0, 1, 2].map((keyEpoch) => ({ pins: set, keyEpoch, expected: core.pinsLegacyWrapAllowed(p, vaultId, keyEpoch) })),
  );
  must(legacyWraps.filter((c) => !c.expected).map((c) => `${c.pins}@${c.keyEpoch}`).join() === "bound@0,bound@1", "v1 wraps are refused other than at or below a recorded v2 epoch");

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
    keyPinsOwn,
    keyPinsBound,
    admissions: admissionCases,
    accepts: acceptCases,
    merges: mergeCases,
    mergesLastKnown: lastKnownCases,
    declines: declineCases,
    observations,
    emails: emailCases,
    legacyWraps,
    ownIdentity: { hash: own, pins: withOwn, checks: ownIdentityCases },
  };
}

// ------------------------------------------------------------ item edit counters (review item 9)

function itemRevVectors(core) {
  const must = (cond, what) => {
    if (!cond) throw new Error(what);
  };
  const account = core.accountFromSessionBytes("rev", new Uint8Array(64).fill(3));
  const key = account.newVaultKey("vault").takeKey();
  const rev = (enc) => key.decryptItem(enc).rev;
  const made = key.encryptItem({ name: "x" }, "item", "vault");
  const edited = key.updateItem(made, { ...key.decryptItem(made), name: "y" });
  const stale = key.updateItem(edited, { name: "z", rev: 0 });
  const restored = key.updateItem(stale, key.decryptItem(made));
  const moved = key.encryptItem(key.decryptItem(restored), "item", "vault");
  const chain = [made, edited, stale, restored, moved].map(rev);
  must(JSON.stringify(chain) === "[1,2,3,4,5]", `the edit counter doesn't count every re-encryption: ${chain}`);
  key.free();
  account.free();
  const checks = [
    [null, 0], [null, 5], [3, 4], [3, 3], [3, 2], [1, 0], [0, 0],
  ].map(([remembered, served]) => ({ remembered, served, expected: core.itemRevCheck(remembered, served) }));
  must(checks.filter((c) => c.expected === "rollback").length === 2, "only a lower counter is a rollback");
  return {
    about: "encryptItem writes rev + 1 of the item given (1 for a new item); updateItem one more than the higher of the stored and the given item's rev; a move or key replacement re-encrypts the decrypted item (+1). `limits`: items sealed here (not by the core) whose stored rev is any number at all: the core reads at most 2^53 − 2 (`reads`) and writes one more than that at most (`writes`: the rev after updateItem, after encryptItem of the decrypted item, and after a move), so no stored rev makes an item impossible to open or save. Open the key with accountFromSessionBytes(accountId, sessionBytes) and openVaultKey(vaultId, wrappedKey, \"account\", keyEpoch, false).",
    chain,
    checks,
    limits: itemRevLimits(core),
  };
}

/** XChaCha20-Poly1305 in the core's ciphertext layout (`0x01 ‖ nonce ‖ ciphertext ‖ tag`). */
function xseal(key, nonce, plaintext, aad) {
  const c = createCipheriv("chacha20-poly1305", hchacha(key, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)]), { authTagLength: 16 });
  c.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([Buffer.from([1]), nonce, body, c.getAuthTag()]);
}

/**
 * Review fix: an item's `rev` is inside the encrypted data, so anyone with the vault key can store
 * any number. Items are sealed here with such numbers (the JSON text is written by hand: JavaScript
 * can't carry most of them) and must open, update, re-encrypt and move through the WASM binding,
 * which before failed on them (the item could never be saved again).
 */
function itemRevLimits(core) {
  const must = (cond, what) => {
    if (!cond) throw new Error(`item rev limits: ${what}`);
  };
  const b64 = (b) => Buffer.from(b).toString("base64url");
  const accountId = "00000000-0000-4000-8000-0000000000d1";
  const vaultId = "00000000-0000-4000-8000-0000000000d2";
  const itemId = "00000000-0000-4000-8000-0000000000d3";
  const keyEpoch = 0;
  const sessionBytes = Buffer.alloc(64, 0x44);
  const rawKey = Buffer.from([...Array(32).keys()].map((i) => 0x40 + i));
  const wrappedKey = b64(Buffer.concat([Buffer.from([2]), xseal(sessionBytes.subarray(0, 32), Buffer.alloc(24, 0x72), rawKey, `passauth/vault-key/v2/${vaultId}/${keyEpoch}`)]));
  const account = core.accountFromSessionBytes(accountId, new Uint8Array(sessionBytes));
  const key = account.openVaultKey(vaultId, wrappedKey, "account", keyEpoch, false);
  const itemKey = Buffer.alloc(32, 0x5a);
  const TOP = 9007199254740990; // 2^53 − 2
  // [the `rev` as it stands in the stored JSON, what the core reads]
  const items = [
    ["18446744073709551615", TOP],
    ["18446744073709551616", TOP],
    ["9007199254740993", TOP],
    ["9007199254740991", TOP],
    ["9007199254740990", TOP],
    ["9007199254740989", TOP - 1],
    ["1e300", TOP],
    ["7", 7],
    ["-3", 0],
  ].map(([rev, reads], n) => {
    const json = `{"format":2,"name":"Item with rev ${rev}","rev":${rev}}`;
    const encrypted = {
      id: itemId,
      vault_id: vaultId,
      key: b64(xseal(rawKey, Buffer.alloc(24, 0x80 + n), itemKey, `passauth/item-key/v1/${vaultId}/${itemId}`)),
      data: b64(xseal(itemKey, Buffer.alloc(24, 0x90 + n), Buffer.from(json, "utf8"), `passauth/item/v1/${vaultId}/${itemId}`)),
    };
    const item = key.decryptItem(encrypted);
    must(item.rev === reads && Number.isSafeInteger(item.rev) && item.name === `Item with rev ${rev}`, `rev ${rev} reads as ${item.rev}`);
    const writes = Math.min(reads, TOP) + 1;
    const after = [
      key.updateItem(encrypted, { ...item, name: "edited" }),
      key.encryptItem(item, itemId, vaultId),
      key.updateItem(encrypted, { name: "from an app that kept nothing" }),
    ].map((e) => key.decryptItem(e).rev);
    // What was written is `writes`; reading it back gives at most the top again.
    must(after.every((r) => r === Math.min(writes, TOP)), `rev ${rev} writes ${after}`);
    must(core.itemRevCheck(reads, Math.min(writes, TOP)) === (reads === TOP ? "same" : "newer"), `rev ${rev}: the counter after a write`);
    return { rev, encrypted, reads, writes };
  });
  // A number JavaScript can't carry, handed back by an app as it got it from elsewhere.
  must(key.decryptItem(key.updateItem(items[0].encrypted, { name: "x", rev: 1e300 })).rev === TOP, "a huge rev given to updateItem");
  must(key.decryptItem(key.encryptItem({ name: "x", rev: 2 ** 60 }, itemId, vaultId)).rev === TOP, "a huge rev given to encryptItem");
  key.free();
  account.free();
  return { accountId, sessionBytes: b64(sessionBytes), vaultId, keyEpoch, wrappedKey, itemId, top: TOP, items };
}

// ------------------------------------------------------------ Send v2 (review item 8)

function sendV2Vectors(core) {
  const must = (cond, what) => {
    if (!cond) throw new Error(what);
  };
  const fixtures = {
    key: Buffer.from([...Array(32).keys()]).toString("base64url"),
    password: "correct horse battery staple",
    // The core's floor: the cheapest parameters a visitor's app accepts.
    salt: `sendpw-v1$m=65536,t=3,p=1$${Buffer.from([...Array(16).keys()].map((i) => i + 1)).toString("base64url")}`,
    text: "Hello from PassAuth Send v2 ✓",
    nonce: "60".repeat(24),
  };
  const saltBytes = Buffer.from(fixtures.salt.split("$")[2], "base64url");
  const stretched = argon2Sync("argon2id", { message: fixtures.password, nonce: saltBytes, parallelism: 1, tagLength: 32, memory: 65536, passes: 3 });
  const hk = (ikm, salt, info) => Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from(info), 32));
  const verifier = hk(stretched, saltBytes, "passauth/send-password/v1").toString("base64url");
  const contentKey = hk(Buffer.from(fixtures.key, "base64url"), hk(stretched, saltBytes, "passauth/send-password-key/v2"), "passauth/send-content/v2");
  const keys = core.sendPasswordKeys(fixtures.password, fixtures.salt, fixtures.key);
  must(keys.verifier === verifier && keys.contentKey === contentKey.toString("base64url"), "the core's Send v2 keys differ from node:crypto's");
  must(core.sendPasswordVerifier(fixtures.password, fixtures.salt) === verifier, "sendPasswordKeys' verifier isn't sendPasswordVerifier's");
  // `0x02 ‖ 0x01 ‖ nonce ‖ ciphertext ‖ tag`, sealed here with a fixed nonce (XChaCha20-Poly1305 via HChaCha20).
  const nonce = Buffer.from(fixtures.nonce, "hex");
  const cipher = createCipheriv("chacha20-poly1305", hchacha(contentKey, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)]), { authTagLength: 16 });
  cipher.setAAD(Buffer.from("passauth/send/v2/data"));
  const sealed = Buffer.concat([cipher.update(Buffer.from(fixtures.text, "utf8")), cipher.final()]);
  const data = Buffer.concat([Buffer.from([2, 1]), nonce, sealed, cipher.getAuthTag()]).toString("base64url");
  must(core.sendOpen(fixtures.key, keys.contentKey, "data", data) === fixtures.text, "the core doesn't open a Send v2 field sealed here");
  must(core.sendFieldVersion(data) === 2, "a v2 field isn't version 2");
  const fails = (f) => {
    try {
      f();
      return null;
    } catch (e) {
      return e.message;
    }
  };
  must(fails(() => core.sendOpen(fixtures.key, null, "data", data)) === "password_required", "a v2 field opened without the password");
  must(fails(() => core.sendOpen(fixtures.key, keys.contentKey, "name", data)) === "decrypt_failed", "a v2 field opened as the other field");
  must(fails(() => core.sendDecrypt(fixtures.key, "data", data)) !== null, "the link key alone opened a v2 field");
  // What the core seals opens here (with the marker and the v2 associated data).
  const ours = Buffer.from(core.sendEncryptV2(keys.contentKey, "name", "Door code"), "base64url");
  must(ours[0] === 2 && ours[1] === 1, "sendEncryptV2 doesn't write the v2 layout");
  const n2 = ours.subarray(2, 26);
  const d = createDecipheriv("chacha20-poly1305", hchacha(contentKey, n2.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), n2.subarray(16)]), { authTagLength: 16 });
  d.setAAD(Buffer.from("passauth/send/v2/name"));
  d.setAuthTag(ours.subarray(ours.length - 16));
  must(Buffer.concat([d.update(ours.subarray(26, ours.length - 16)), d.final()]).toString("utf8") === "Door code", "sendEncryptV2's output doesn't open here");
  // v1 fields open with the link key alone, as before.
  const v1 = core.sendEncrypt(fixtures.key, "data", "plain");
  must(core.sendFieldVersion(v1) === 1 && core.sendOpen(fixtures.key, null, "data", v1) === "plain", "a v1 field doesn't open as before");
  // The owner's copy of the content key.
  const owner = core.accountFromSessionBytes("owner", new Uint8Array(64).fill(4));
  must(owner.unwrapSendContentKey(owner.wrapSendContentKey(keys.contentKey)) === keys.contentKey, "owner_content_key doesn't round-trip");
  owner.free();
  keys.free();
  return { ...fixtures, verifier, contentKey: contentKey.toString("base64url"), data };
}

// ------------------------------------------------------------ vault manifests

/**
 * Vault manifests (crates/core/src/manifest.rs). A fixed account (session bytes) and a fixed vault
 * key, wrapped here for that account with a fixed nonce (the v2 account wrap), so every client's
 * tests open the same key through their binding. Independently of the core this computes each
 * item's term (HMAC-SHA256 under the HKDF mac key of `id ‖ 0 ‖ state ‖ 0 ‖ SHA-256(data)`), the
 * sum mod 2^256 and the counts, seals the manifest with a fixed nonce (the associated data names
 * the link of the manifest it replaces), computes every link, and opens what the core seals.
 * `manifests` are vault rows as a server lists them, `checks` every verdict of `manifestVerify`
 * (with what the device remembers and, where it has one, the log), `writes` what `manifestNext`
 * must add up to, `starts` what `manifestStart` must name.
 */
function vaultManifestVectors(core) {
  const must = (cond, what) => {
    if (!cond) throw new Error(`vault manifest: ${what}`);
  };
  const b64 = (b) => Buffer.from(b).toString("base64url");
  const sha256 = (text) => createHash("sha256").update(Buffer.from(text, "utf8")).digest();
  const hk = (ikm, info) => Buffer.from(hkdfSync("sha256", ikm, Buffer.alloc(0), Buffer.from(info), 32));
  const seal = xseal;
  const open = (key, blob, aad) => {
    must(blob[0] === 1, "unknown ciphertext version");
    const nonce = blob.subarray(1, 25);
    const d = createDecipheriv("chacha20-poly1305", hchacha(key, nonce.subarray(0, 16)), Buffer.concat([Buffer.alloc(4), nonce.subarray(16)]), { authTagLength: 16 });
    d.setAAD(Buffer.from(aad, "utf8"));
    d.setAuthTag(blob.subarray(blob.length - 16));
    return Buffer.concat([d.update(blob.subarray(25, blob.length - 16)), d.final()]);
  };

  const accountId = "00000000-0000-4000-8000-0000000000e1";
  const vaultId = "00000000-0000-4000-8000-0000000000e2";
  const keyEpoch = 2;
  const sessionBytes = Buffer.alloc(64, 0x33);
  const rawKey = Buffer.from([...Array(32).keys()].map((i) => 0xa0 + i));
  const wrap = (raw, epoch, nonceByte) => b64(Buffer.concat([Buffer.from([2]), seal(sessionBytes.subarray(0, 32), Buffer.alloc(24, nonceByte), raw, `passauth/vault-key/v2/${vaultId}/${epoch}`)]));
  const wrappedKey = wrap(rawKey, keyEpoch, 0x71);
  // The key after a key replacement: another key, the next epoch.
  const rotatedRaw = Buffer.from([...Array(32).keys()].map((i) => 0xc0 + i));
  const rotatedWrapped = wrap(rotatedRaw, keyEpoch + 1, 0x73);
  const account = core.accountFromSessionBytes(accountId, new Uint8Array(sessionBytes));
  const key = account.openVaultKey(vaultId, wrappedKey, "account", keyEpoch, false);
  const rotatedKey = account.openVaultKey(vaultId, rotatedWrapped, "account", keyEpoch + 1, false);
  const macKeyOf = (raw) => hk(raw, "passauth/vault-manifest-mac/v1");
  const sealKeyOf = (raw) => hk(raw, "passauth/vault-manifest-key/v1");
  const NO_LINK = Buffer.alloc(32);
  const aadOf = (version, prev, epoch = keyEpoch, vault = vaultId) => `passauth/vault-manifest/v1/${vault}/${epoch}/${version}/${prev.toString("hex")}`;
  // link = SHA-256("passauth/vault-manifest-link/v1" ‖ 0x00 ‖ version (8 bytes BE) ‖ prev ‖ SHA-256(sealed text))
  const linkOf = (seq, prev, sealedText) => {
    const version = Buffer.alloc(8);
    version.writeBigUInt64BE(BigInt(seq));
    return createHash("sha256").update(Buffer.concat([Buffer.from("passauth/vault-manifest-link/v1"), Buffer.from([0]), version, prev, sha256(sealedText)])).digest();
  };

  const term = (id, trashed, data, raw = rawKey) => createHmac("sha256", macKeyOf(raw)).update(Buffer.concat([Buffer.from(id, "utf8"), Buffer.from([0, trashed ? 1 : 0, 0]), sha256(data)])).digest();
  const M = 1n << 256n;
  const num = (buf) => BigInt(`0x${buf.toString("hex")}`);
  const bytes32 = (n) => Buffer.from((((n % M) + M) % M).toString(16).padStart(64, "0"), "hex");
  // The one rule for every client: in the trash exactly when `deleted_at` is not null.
  const trashedOf = (row) => row.deleted_at != null;
  const summary = (rows, raw = rawKey) => ({
    live: rows.filter((r) => !trashedOf(r)).length,
    trashed: rows.filter(trashedOf).length,
    acc: bytes32(rows.reduce((sum, r) => sum + num(term(r.id, trashedOf(r), r.data, raw)), 0n)),
  });
  /** A stored manifest as a vault row lists it (plus its link and the epoch it is sealed for). */
  const stored = (version, rows, nonceByte, prev, { epoch = keyEpoch, vault = vaultId, raw = rawKey, says = version } = {}) => {
    const s = summary(rows, raw);
    const json = JSON.stringify({ version: says, live: s.live, trashed: s.trashed, acc: b64(s.acc) });
    const sealed = b64(seal(sealKeyOf(raw), Buffer.alloc(24, nonceByte), Buffer.from(json, "utf8"), aadOf(version, prev, epoch, vault)));
    return { manifest_seq: version, manifest_prev: b64(prev), manifest: sealed, link: b64(linkOf(version, prev, sealed)), keyEpoch: epoch };
  };
  const linkBytes = (m) => Buffer.from(m.link, "base64url");
  const opened = (m, raw = rawKey) => JSON.parse(open(sealKeyOf(raw), Buffer.from(m.manifest, "base64url"), aadOf(m.manifest_seq, Buffer.from(m.manifest_prev, "base64url"), m.keyEpoch)).toString("utf8"));

  // Rows as `/sync` sends them (the fields a manifest reads, plus one it ignores). `data` is any
  // text: only its bytes count.
  const id = (n) => `00000000-0000-4000-8000-00000000010${n}`;
  const items = [
    { id: id(1), vault_id: vaultId, deleted_at: null, data: "AbCdEf0123456789-_first", revision: 11 },
    { id: id(2), vault_id: vaultId, deleted_at: null, data: "AbCdEf0123456789-_second", revision: 12 },
    { id: id(3), vault_id: vaultId, deleted_at: 1763400000, data: "AbCdEf0123456789-_third", revision: 13 },
  ];
  const hashOf = (row) => b64(sha256(row.data));
  // `trash=summary`: the trashed row without its data, with the server's hash of it.
  const summaryItems = items.map((r) => (trashedOf(r) ? { id: r.id, vault_id: r.vault_id, deleted_at: r.deleted_at, data_sha256: hashOf(r), revision: r.revision } : r));
  // The items as a key replacement re-encrypts them (other data, the same ids and states).
  const rotatedItems = items.map((r) => ({ ...r, data: `${r.data}-under-the-new-key` }));
  const variants = {
    full: items,
    summary: summaryItems,
    reordered: [...items].reverse(),
    hidden: items.slice(0, 2),
    resurrected: [...items, { id: id(4), deleted_at: null, data: "AbCdEf0123456789-_fourth" }],
    older: [{ ...items[0], data: "AbCdEf0123456789-_first-before" }, items[1], items[2]],
    restored: [items[0], items[1], { ...items[2], deleted_at: null }],
    trashed: [{ ...items[0], deleted_at: 1763400001 }, items[1], items[2]],
    wrongHash: [items[0], items[1], { ...summaryItems[2], data_sha256: b64(sha256("something else")) }],
    noHash: [items[0], items[1], { id: items[2].id, deleted_at: items[2].deleted_at }],
    // A `trashed` field in a row is never read: only `deleted_at` says where an item is.
    trashedFieldIgnored: [{ ...items[0], trashed: true }, items[1], { ...items[2], trashed: false }],
    rotated: rotatedItems,
    empty: [],
  };
  // Rows no client may count (review fix): `deleted_at` is null/absent or a whole number above 0.
  const malformed = [0, -1, 0.5, 1763400000.5, "1763400000", "", true, false].map((deletedAt) => ({
    deletedAt,
    items: [items[0], items[1], { ...items[2], deleted_at: deletedAt }],
  }));

  // The history: version 1 (the vault empty), then the three items from version 2 on.
  const m1 = stored(1, [], 0x56, NO_LINK);
  const m2 = stored(2, items, 0x57, linkBytes(m1));
  const current = stored(3, items, 0x51, linkBytes(m2));
  const m4 = stored(4, items, 0x58, linkBytes(current));
  const m5 = stored(5, items, 0x59, linkBytes(m4));
  // A second history from version 2 (what a server shows another device).
  const f3 = stored(3, items, 0x5a, linkBytes(m2));
  const f4 = stored(4, items, 0x5b, linkBytes(f3));
  const f5 = stored(5, items, 0x5c, linkBytes(f4));
  // A key replacement after version 5: the new key, the next epoch, the re-encrypted items.
  const r6 = stored(6, rotatedItems, 0x5d, linkBytes(m5), { epoch: keyEpoch + 1, raw: rotatedRaw });
  const r7 = stored(7, rotatedItems, 0x5e, linkBytes(r6), { epoch: keyEpoch + 1, raw: rotatedRaw });
  // A baseline ("Use the server's copy") by a device that was shown the second history: the next
  // version, like every write.
  const b6 = stored(6, items, 0x5f, linkBytes(f5));
  const version = current.manifest_seq;
  const total = summary(items);
  const terms = items.map((r) => ({ id: r.id, trashed: trashedOf(r), dataSha256: hashOf(r), term: term(r.id, trashedOf(r), r.data).toString("hex") }));
  for (const r of items) must(core.manifestDataHash(r.data) === hashOf(r), "manifestDataHash differs from SHA-256");

  const manifests = {
    first: m1,
    second: m2,
    current,
    fourth: m4,
    fifth: m5,
    forkThird: f3,
    forkFourth: f4,
    forkFifth: f5,
    rotated: r6,
    rotatedNext: r7,
    baseline: b6,
    // The current manifest listed with another version, or another predecessor.
    relabelled: { ...current, manifest_seq: 4 },
    otherPrev: { ...current, manifest_prev: b64(NO_LINK) },
    noPrev: { ...current, manifest_prev: null },
    noText: { ...current, manifest: null },
    otherEpoch: stored(3, items, 0x53, linkBytes(m2), { epoch: keyEpoch + 1 }),
    otherVault: stored(3, items, 0x54, linkBytes(m2), { vault: id(9) }),
    // Sealed for version 3 but saying 4 inside.
    lyingVersion: stored(3, items, 0x55, linkBytes(m2), { says: 4 }),
    garbage: { ...current, manifest: "AAAA" },
    none: { manifest_seq: 0, manifest_prev: null, manifest: null, keyEpoch },
    // Version 0 with a text left over: no manifest all the same.
    noneWithText: { ...current, manifest_seq: 0 },
  };
  const linkable = Object.entries(manifests).filter(([, m]) => m.manifest_seq > 0 && m.manifest_prev && m.manifest);
  for (const [name, m] of linkable) {
    const link = b64(linkOf(m.manifest_seq, Buffer.from(m.manifest_prev, "base64url"), m.manifest));
    must(core.manifestLink(m.manifest_seq, m.manifest_prev, m.manifest) === link, `${name}: manifestLink differs from the hash computed here`);
    m.link = link;
  }
  for (const name of ["none", "noPrev", "noText", "noneWithText"]) manifests[name].link = null;

  // What the core seals for the same items opens here to the same record, and names the same links.
  const own = key.manifestStart(vaultId, keyEpoch, version, m2.link, items);
  must(own.seq === version && own.prev === m2.link && own.link === b64(linkOf(version, linkBytes(m2), own.sealed)), "manifestStart's seq, prev or link differ");
  const ownRecord = opened({ manifest_seq: version, manifest_prev: own.prev, manifest: own.sealed, keyEpoch });
  must(ownRecord.version === version && ownRecord.live === total.live && ownRecord.trashed === total.trashed && ownRecord.acc === b64(total.acc), "manifestStart differs from the sum computed here");
  const byHash = key.manifestStart(vaultId, keyEpoch, version, m2.link, summaryItems);
  must(JSON.stringify(opened({ manifest_seq: version, manifest_prev: byHash.prev, manifest: byHash.sealed, keyEpoch })) === JSON.stringify(ownRecord), "a row counted by its hash differs");
  const firstOwn = key.manifestStart(vaultId, keyEpoch, 1, null, []);
  must(firstOwn.prev === b64(NO_LINK), "a first manifest names a predecessor");

  const seenOf = (m) => ({ version: m.manifest_seq, link: m.link });
  const logOf = (...list) => list.map((m) => ({ seq: m.manifest_seq, prev: m.manifest_prev, digest: b64(sha256(m.manifest)) }));
  const mainLog = logOf(m1, m2, current, m4, m5);
  const forkLog = logOf(m1, m2, f3, f4, f5);
  const elsewhere = { version: 4, link: b64(sha256("a manifest this server never showed")) };
  // Entries no walk may reach and no binding may throw on (all of it valid JSON).
  const rubbish = [
    null,
    true,
    7,
    -7,
    1.5,
    "text",
    [],
    [1, [2]],
    {},
    { seq: 3 },
    { seq: -1, prev: m2.link, digest: m2.link },
    { seq: 0, prev: m2.link, digest: m2.link },
    { seq: 2.5, prev: m2.link, digest: m2.link },
    { seq: "3", prev: m2.link, digest: m2.link },
    { seq: null, prev: m2.link, digest: m2.link },
    { seq: 3, prev: 4, digest: m2.link },
    { seq: 3, prev: m2.link, digest: null },
    { seq: 3, prev: m2.link, digest: [m2.link] },
    { seq: 3, prev: m2.link },
    { seq: { n: 3 }, prev: m2.link, digest: m2.link },
  ];
  // [name, row (a name in `manifests`), remembered, log, items (a name in `items`), expected status, key]
  const checks = [
    // Nothing remembered: the first manifest a device sees is trusted.
    ["first sight", "current", null, null, "full", "ok"],
    ["first sight, summary rows", "current", null, null, "summary", "ok"],
    ["first sight, any order", "current", null, null, "reordered", "ok"],
    ["first sight, a `trashed` field is ignored", "current", null, null, "trashedFieldIgnored", "ok"],
    ["first sight of the empty vault", "first", null, null, "empty", "ok"],
    ["no manifest, none seen", "none", null, null, "full", "none"],
    ["no manifest, none seen, no items", "none", null, null, "empty", "none"],
    ["version 0 ignores a text", "noneWithText", null, null, "full", "none"],
    // The same manifest again, the next one, and one further on.
    ["the remembered manifest", "current", seenOf(current), null, "full", "ok"],
    ["one step ahead", "current", seenOf(m2), null, "summary", "ok"],
    ["two steps ahead, no log yet", "current", seenOf(m1), null, "full", "need_log"],
    ["two steps ahead, with the log", "current", seenOf(m1), logOf(m2), "full", "ok"],
    ["four steps ahead, with the log", "fifth", seenOf(m1), mainLog, "full", "ok"],
    ["four steps ahead, the log reversed and with strangers", "fifth", seenOf(m1), [...logOf(f5, f4, f3), ...mainLog].reverse(), "full", "ok"],
    ["the log starts right after the remembered one", "fifth", seenOf(m2), logOf(current, m4), "full", "ok"],
    // Rollback: a lower version than remembered, or none.
    ["a lower version", "current", seenOf(m4), null, "full", "rollback"],
    ["a lower version, whatever the history", "current", elsewhere, null, "full", "rollback"],
    ["no manifest after one was seen", "none", seenOf(m1), null, "full", "rollback"],
    ["a lower version comes before the items", "current", seenOf(m5), null, "noHash", "rollback"],
    // Fork: another history at the same version, or joined later.
    ["another manifest at the remembered version", "forkThird", seenOf(current), null, "full", "mismatch"],
    ["the other way round", "current", seenOf(f3), null, "full", "mismatch"],
    // The very next version naming another predecessor is settled without the log (review fix).
    ["joined one version later, no log needed", "forkFourth", seenOf(current), null, "full", "mismatch"],
    ["joined one version later, its log", "forkFourth", seenOf(current), forkLog, "full", "mismatch"],
    ["joined two versions later, no log yet", "forkFifth", seenOf(current), null, "full", "need_log"],
    ["joined two versions later, its log", "forkFifth", seenOf(current), forkLog, "full", "mismatch"],
    ["joined later, both histories' logs", "forkFifth", seenOf(m4), [...forkLog, ...mainLog], "full", "mismatch"],
    ["joined later, an empty log", "forkFifth", seenOf(current), [], "full", "mismatch"],
    ["a device from before the fork follows either", "forkFifth", seenOf(m2), forkLog, "full", "ok"],
    ["a manifest from a history never seen", "fifth", elsewhere, mainLog, "full", "mismatch"],
    // A log cut short (pruned or withheld) or changed is not a pass.
    ["a pruned log", "fifth", seenOf(m1), logOf(m4), "full", "mismatch"],
    ["a log with a hole", "fifth", seenOf(m1), logOf(m2, m4), "full", "mismatch"],
    ["a log entry renumbered", "fifth", seenOf(m1), mainLog.map((e) => (e.seq === 3 ? { ...e, seq: 2 } : e)), "full", "mismatch"],
    ["a log entry with another digest", "fifth", seenOf(m1), mainLog.map((e) => (e.seq === 3 ? { ...e, digest: b64(sha256("x")) } : e)), "full", "mismatch"],
    ["a log entry that is no link", "fifth", seenOf(m2), [{ seq: 3, prev: "AAAA", digest: "AAAA" }, ...logOf(m4)], "full", "mismatch"],
    // Rubbish in a log is skipped, never an error (review fix): pass the log as the server sent it.
    ["a log with rubbish around the real entries", "fifth", seenOf(m1), [...rubbish, ...mainLog, ...rubbish], "full", "ok"],
    ["a log of rubbish alone", "fifth", seenOf(m1), rubbish, "full", "mismatch"],
    // The row itself.
    ["no text", "noText", null, null, "full", "mismatch"],
    ["no predecessor listed", "noPrev", null, null, "full", "mismatch"],
    ["another predecessor listed", "otherPrev", null, null, "full", "mismatch"],
    ["another version listed", "relabelled", null, null, "full", "mismatch"],
    ["another version listed, one step ahead", "relabelled", seenOf(current), null, "full", "mismatch"],
    ["sealed for another epoch", "otherEpoch", null, null, "full", "mismatch"],
    ["sealed for another vault", "otherVault", null, null, "full", "mismatch"],
    ["another version inside", "lyingVersion", null, null, "full", "mismatch"],
    ["not a manifest", "garbage", null, null, "full", "mismatch"],
    // The items.
    ["an item hidden", "current", null, null, "hidden", "mismatch"],
    ["an item brought back", "current", null, null, "resurrected", "mismatch"],
    ["an older copy of an item", "current", seenOf(m2), null, "older", "mismatch"],
    ["an item out of the trash", "current", null, null, "restored", "mismatch"],
    ["an item into the trash", "current", null, null, "trashed", "mismatch"],
    ["another hash for a row without data", "current", null, null, "wrongHash", "mismatch"],
    ["a row without data or hash", "current", null, null, "noHash", "incomplete"],
    ["a row without data or hash comes before the log", "current", seenOf(m1), null, "noHash", "incomplete"],
    ["wrong items come before the log", "current", seenOf(m1), null, "hidden", "mismatch"],
    ["items in an empty vault", "first", null, null, "full", "mismatch"],
    // Key replacement: the chain goes on under the new key; the old key opens nothing of it.
    ["after a key replacement, one step ahead", "rotated", seenOf(m5), null, "rotated", "ok", "rotated"],
    ["after a key replacement, first sight", "rotated", null, null, "rotated", "ok", "rotated"],
    ["after a key replacement, from the old epoch by the log", "rotatedNext", seenOf(current), logOf(m4, m5, r6), "rotated", "ok", "rotated"],
    ["after a key replacement, from the other history", "rotatedNext", seenOf(f3), logOf(m4, m5, r6), "rotated", "mismatch", "rotated"],
    ["after a key replacement, the old key", "rotated", seenOf(m5), null, "rotated", "mismatch"],
    ["after a key replacement, the old items", "rotated", seenOf(m5), null, "full", "mismatch", "rotated"],
    // Baseline: accepted by its writer and by devices on the history it was built on.
    ["a baseline, its writer", "baseline", seenOf(b6), null, "full", "ok"],
    ["a baseline, first sight", "baseline", null, null, "full", "ok"],
    ["a baseline, a device on the history it replaced", "baseline", seenOf(f5), null, "full", "ok"],
    ["a baseline, a device further back on that history", "baseline", seenOf(m2), logOf(f3, f4, f5), "full", "ok"],
    ["a baseline, a device on the other history", "baseline", seenOf(m5), null, "full", "mismatch"],
    ["a baseline, a device on the other history, with the logs", "baseline", seenOf(m5), logOf(f3, f4, f5, m4, m5), "full", "mismatch"],
    ["a baseline, a device further back on the other history, no log yet", "baseline", seenOf(m4), null, "full", "need_log"],
    ["a baseline, a device further back on the other history", "baseline", seenOf(m4), logOf(f3, f4, f5, m4, m5), "full", "mismatch"],
    ["a baseline, a device that saw a later version", "baseline", seenOf(r7), null, "full", "rollback"],
  ].map(([name, rowName, remembered, log, rows, status, keyName = "main"]) => {
    const row = manifests[rowName];
    const k = keyName === "rotated" ? rotatedKey : key;
    const epoch = keyName === "rotated" ? keyEpoch + 1 : keyEpoch;
    const expected = k.manifestVerify(vaultId, epoch, row.manifest_seq, row.manifest_prev, row.manifest, remembered?.version ?? null, remembered?.link ?? null, log, variants[rows]);
    must(expected.status === status, `"${name}" should be ${status}, is ${JSON.stringify(expected)}`);
    // What to remember: the served manifest for "ok", otherwise what was remembered, unchanged.
    const keeps = status === "ok" ? { version: row.manifest_seq, link: row.link } : { version: remembered?.version ?? 0, link: remembered?.link ?? null };
    must(expected.version === keeps.version && expected.link === keeps.link, `"${name}" remembers ${JSON.stringify(expected)}`);
    return { name, manifest: rowName, key: keyName, keyEpoch: epoch, remembered, log, items: rows, expected };
  });
  must(JSON.stringify(checks[0].expected) === JSON.stringify({ status: "ok", version: 3, link: current.link, live: 2, trashed: 1 }), `the first check isn't ok: ${JSON.stringify(checks[0].expected)}`);
  for (const status of ["none", "ok", "rollback", "mismatch", "incomplete", "need_log"]) must(checks.some((c) => c.expected.status === status), `no check is ${status}`);
  // Another key doesn't open it.
  const otherKey = account.newVaultKey(vaultId).takeKey();
  must(otherKey.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, null, null, null, items).status === "mismatch", "another key opened the manifest");
  otherKey.free();

  const fails = (f) => {
    try {
      f();
      return false;
    } catch {
      return true;
    }
  };
  // Rows that can't be counted are refused by every entry point, never read as live or trashed.
  for (const bad of malformed) {
    must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, null, null, null, bad.items)), `deleted_at ${JSON.stringify(bad.deletedAt)} was counted by manifestVerify`);
    must(fails(() => key.manifestStart(vaultId, keyEpoch, 1, null, bad.items)), `deleted_at ${JSON.stringify(bad.deletedAt)} was counted by manifestStart`);
    must(fails(() => key.manifestNext(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, [bad.items[2]], [])), `deleted_at ${JSON.stringify(bad.deletedAt)} was counted by manifestNext (removed)`);
    must(fails(() => key.manifestNext(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, [], [bad.items[2]])), `deleted_at ${JSON.stringify(bad.deletedAt)} was counted by manifestNext (added)`);
  }
  // Half a memory is a bug in the caller, not "nothing remembered".
  must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, 3, null, null, items)), "a remembered version without its link was accepted");
  must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, null, current.link, null, items)), "a remembered link without its version was accepted");
  must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, 0, current.link, null, items)), "a remembered version 0 was accepted");
  // A memory that can't be one (review fix: the link no manifest has, 32 zero bytes, among them).
  const badMemories = [
    { version: 2, link: b64(NO_LINK) },
    { version: 3, link: b64(NO_LINK) },
    { version: 0, link: m2.link },
    { version: 2, link: "AAAA" },
    { version: 2, link: `${m2.link}A` },
    { version: 2, link: "" },
  ];
  for (const bad of badMemories) must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, bad.version, bad.link, null, items)), `the memory ${JSON.stringify(bad)} was accepted`);
  // A log that is no list throws; rubbish inside a list never does (the checks above).
  for (const bad of [{}, { entries: [] }, 7, "[]"]) must(fails(() => key.manifestVerify(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, 1, m1.link, bad, items)), `the log ${JSON.stringify(bad)} was taken`);

  // "Use the server's copy": the served vault judged with nothing remembered. `ok` = replace the
  // device's memory with {version, link}; `none` = forget it; anything else = remember nothing.
  // [name, row, items, expected status, key]
  const accepts = [
    ["the served manifest records the served items", "current", "full", "ok"],
    ["the same from summary rows", "current", "summary", "ok"],
    ["an older state of the vault (a restored backup)", "second", "full", "ok"],
    ["the other history", "forkFifth", "full", "ok"],
    ["a baseline", "baseline", "full", "ok"],
    ["after a key replacement", "rotatedNext", "rotated", "ok", "rotated"],
    ["no manifest served", "none", "full", "none"],
    ["version 0 with a text left over", "noneWithText", "full", "none"],
    ["an item hidden", "current", "hidden", "mismatch"],
    ["an item brought back", "current", "resurrected", "mismatch"],
    ["an older copy of an item", "current", "older", "mismatch"],
    ["a manifest that doesn't open", "garbage", "full", "mismatch"],
    ["another predecessor listed", "otherPrev", "full", "mismatch"],
    ["no predecessor listed", "noPrev", "full", "mismatch"],
    ["another version listed", "relabelled", "full", "mismatch"],
    ["the old key after a key replacement", "rotated", "rotated", "mismatch"],
    ["a row without data or hash", "current", "noHash", "incomplete"],
  ].map(([name, rowName, rows, status, keyName = "main"]) => {
    const row = manifests[rowName];
    const k = keyName === "rotated" ? rotatedKey : key;
    const epoch = keyName === "rotated" ? keyEpoch + 1 : keyEpoch;
    const expected = k.manifestAccept(vaultId, epoch, row.manifest_seq, row.manifest_prev, row.manifest, variants[rows]);
    must(expected.status === status, `accept "${name}" should be ${status}, is ${JSON.stringify(expected)}`);
    const keeps = status === "ok" ? { version: row.manifest_seq, link: row.link } : { version: 0, link: null };
    must(expected.version === keeps.version && expected.link === keeps.link, `accept "${name}" remembers ${JSON.stringify(expected)}`);
    // The same verdict as the check with nothing remembered, and what it gives is a memory the
    // check then takes.
    const plain = k.manifestVerify(vaultId, epoch, row.manifest_seq, row.manifest_prev, row.manifest, null, null, null, variants[rows]);
    must(JSON.stringify(plain) === JSON.stringify(expected), `accept "${name}" differs from the check without a memory`);
    if (status === "ok") must(k.manifestVerify(vaultId, epoch, row.manifest_seq, row.manifest_prev, row.manifest, expected.version, expected.link, null, variants[rows]).status === "ok", `accept "${name}": the accepted memory doesn't check out`);
    return { name, manifest: rowName, key: keyName, keyEpoch: epoch, items: rows, expected };
  });
  for (const bad of malformed) must(fails(() => key.manifestAccept(vaultId, keyEpoch, 3, current.manifest_prev, current.manifest, bad.items)), `deleted_at ${JSON.stringify(bad.deletedAt)} was counted by manifestAccept`);

  // Writes: `removed` as the items were, `added` as they are afterwards.
  const edited = { ...items[0], data: "AbCdEf0123456789-_first-edited" };
  const created = { id: id(5), deleted_at: null, data: "AbCdEf0123456789-_fifth" };
  const writes = [
    { name: "create", removed: [], added: [created] },
    { name: "edit", removed: [items[0]], added: [edited] },
    { name: "trash", removed: [items[1]], added: [{ ...items[1], deleted_at: 1763400002 }] },
    { name: "restore", removed: [summaryItems[2]], added: [{ ...summaryItems[2], deleted_at: null }] },
    { name: "delete for good", removed: [summaryItems[2]], added: [] },
    { name: "move out", removed: [items[0]], added: [] },
    { name: "import", removed: [], added: [created, { id: id(6), deleted_at: null, data: "AbCdEf0123456789-_sixth" }] },
    { name: "nothing", removed: [], added: [] },
  ].map((w) => {
    const gone = new Set(w.removed.map((r) => r.id));
    const full = (r) => (r.data === undefined ? { ...r, data: items.find((i) => i.id === r.id).data } : r);
    const after = [...items.filter((r) => !gone.has(r.id)), ...w.added.map(full)];
    const next = key.manifestNext(vaultId, keyEpoch, version, current.manifest_prev, current.manifest, w.removed, w.added);
    must(next.seq === version + 1, `${w.name}: not one version up`);
    must(next.prev === current.link, `${w.name}: doesn't name the manifest it replaces`);
    must(next.link === b64(linkOf(next.seq, linkBytes(current), next.sealed)), `${w.name}: the link differs from the hash computed here`);
    const expected = summary(after);
    const got = opened({ manifest_seq: next.seq, manifest_prev: next.prev, manifest: next.sealed, keyEpoch });
    must(got.version === version + 1 && got.live === expected.live && got.trashed === expected.trashed && got.acc === b64(expected.acc), `${w.name}: manifestNext differs from the sum computed here`);
    const check = key.manifestVerify(vaultId, keyEpoch, next.seq, next.prev, next.sealed, version, current.link, null, after);
    must(check.status === "ok" && check.version === next.seq && check.link === next.link, `${w.name}: the next manifest doesn't check out`);
    return { ...w, after, expected: { seq: next.seq, prev: next.prev, live: expected.live, trashed: expected.trashed, acc: expected.acc.toString("hex") } };
  });
  // Starts: what `manifestStart` names as the predecessor, and that the result checks out.
  const starts = [
    { name: "a vault's first manifest", key: "main", keyEpoch, version: 1, prev: null, items: "full", remembered: null },
    { name: "a key replacement's manifest", key: "rotated", keyEpoch: keyEpoch + 1, version: 6, prev: m5.link, items: "rotated", remembered: seenOf(m5) },
    // A baseline is one version above the row it replaces, whatever the device remembered.
    { name: "a baseline on the manifest the server shows", key: "main", keyEpoch, version: f5.manifest_seq + 1, prev: f5.link, items: "full", remembered: seenOf(f5) },
    { name: "a baseline on a manifest that doesn't open", key: "main", keyEpoch, version: manifests.garbage.manifest_seq + 1, prev: manifests.garbage.link, items: "full", remembered: null },
  ].map((s) => {
    const k = s.key === "rotated" ? rotatedKey : key;
    const w = k.manifestStart(vaultId, s.keyEpoch, s.version, s.prev, variants[s.items]);
    const prev = s.prev ?? b64(NO_LINK);
    must(w.seq === s.version && w.prev === prev && w.link === b64(linkOf(w.seq, Buffer.from(prev, "base64url"), w.sealed)), `${s.name}: seq, prev or link differ`);
    const check = k.manifestVerify(vaultId, s.keyEpoch, w.seq, w.prev, w.sealed, s.remembered?.version ?? null, s.remembered?.link ?? null, null, variants[s.items]);
    must(check.status === "ok" && check.link === w.link, `${s.name}: doesn't check out`);
    return { ...s, expected: { seq: s.version, prev } };
  });
  must(fails(() => key.manifestNext(vaultId, keyEpoch, 1, m1.manifest_prev, m1.manifest, [items[0]], [])), "removing from an empty vault was accepted");
  must(fails(() => key.manifestNext(vaultId, keyEpoch, version + 1, current.manifest_prev, current.manifest, [], [])), "manifestNext opened another version");
  must(fails(() => key.manifestNext(vaultId, keyEpoch, version, b64(NO_LINK), current.manifest, [], [])), "manifestNext opened a manifest with another predecessor");
  must(fails(() => key.manifestNext(vaultId, keyEpoch, version, current.manifest_prev, current.manifest, [], [variants.noHash[2]])), "an added item without data was accepted");
  must(fails(() => key.manifestStart(vaultId, keyEpoch, 1, null, variants.noHash)), "manifestStart accepted an item without data");
  must(fails(() => key.manifestStart(vaultId, keyEpoch, 0, null, items)), "version 0 was sealed");
  must(fails(() => key.manifestStart(vaultId, keyEpoch, 2, "AAAA", items)), "manifestStart accepted a predecessor that is no link");
  must(fails(() => key.manifestVerify(vaultId, keyEpoch, version, current.manifest_prev, current.manifest, null, null, null, [...items, items[0]])), "an item listed twice was accepted");
  must(fails(() => core.manifestLink(0, current.manifest_prev, current.manifest)), "manifestLink accepted version 0");
  must(fails(() => core.manifestLink(3, "AAAA", current.manifest)), "manifestLink accepted a predecessor that is no link");
  key.free();
  rotatedKey.free();
  account.free();

  return {
    about: "term = HMAC-SHA256(HKDF(vault key, info passauth/vault-manifest-mac/v1), id ‖ 0x00 ‖ state (0 live, 1 trashed) ‖ 0x00 ‖ SHA-256(data text)); acc = sum of the terms mod 2^256 (big-endian); link = SHA-256(\"passauth/vault-manifest-link/v1\" ‖ 0x00 ‖ version (8 bytes, big-endian) ‖ prev (32 bytes; zero for a first manifest) ‖ SHA-256(sealed text)); sealed with HKDF(vault key, info passauth/vault-manifest-key/v1), associated data passauth/vault-manifest/v1/<vault id>/<key epoch>/<version>/<prev in hex>. An item is in the trash exactly when its deleted_at is not null; deleted_at must be null/absent or a whole number above 0 (`malformed`: every entry point throws). Keys: accountFromSessionBytes(accountId, sessionBytes), then openVaultKey(vaultId, wrappedKey, \"account\", keyEpoch, false) for `main` and openVaultKey(vaultId, rotated.wrappedKey, \"account\", rotated.keyEpoch, false) for `rotated`. `manifests`: vault rows (manifest_seq, manifest_prev, manifest) with their link (manifestLink must give it). `checks`: manifestVerify(vaultId, keyEpoch of the check, the row of `manifest`, remembered version and link or none, log or none, items[`items`]) with that check's key gives `expected` exactly. `writes`: manifestNext on `manifests.current` gives seq and prev of `expected`, opens to its counts and sum, and checks out against `after` for a device that remembers `current`. `starts`: manifestStart(vaultId, keyEpoch, version, prev, items[`items`]) with that key gives seq and prev of `expected` and checks out for `remembered`. `accepts`: manifestAccept(vaultId, keyEpoch of the entry, the row of `manifest`, items[`items`]) with that entry's key gives `expected` exactly (ok: replace the device's memory with version and link; none: forget it; else remember nothing). `badMemories`: manifestVerify throws for each as the remembered pair. Log entries in `checks` are passed as they are, rubbish included: no binding may throw on them.",
    accountId,
    sessionBytes: b64(sessionBytes),
    vaultId,
    keyEpoch,
    wrappedKey,
    vaultKey: rawKey.toString("hex"),
    rotated: { keyEpoch: keyEpoch + 1, wrappedKey: rotatedWrapped, vaultKey: rotatedRaw.toString("hex") },
    version,
    live: total.live,
    trashed: total.trashed,
    acc: total.acc.toString("hex"),
    terms,
    items: variants,
    malformed,
    manifests: Object.fromEntries(Object.entries(manifests).map(([name, { keyEpoch: _sealedFor, ...row }]) => [name, row])),
    checks,
    accepts,
    badMemories,
    writes,
    starts,
  };
}

/** HChaCha20 (the XChaCha20 subkey) of a 32-byte key and a 16-byte nonce. */
function hchacha(key, nonce16) {
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
