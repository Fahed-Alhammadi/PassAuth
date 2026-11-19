import { describe, expect, it } from "vitest";
import {
  APP_RETURN,
  KEY_DONE_PATH,
  KeyPageWaiter,
  b64urlToBytes,
  bytesToB64url,
  CONTEXT_ENDED,
  allowedRequest,
  challengeOf,
  contextLine,
  fetchContext,
  isKeyPagePath,
  jsonToB64url,
  keyPageUrl,
  parseKeyPageFragment,
  parseReturnFragment,
  readContext,
  returnTarget,
  validState,
} from "./key-page";

const CHALLENGE = bytesToB64url(new Uint8Array(32).map((_, i) => i * 7 + 1));
const OTHER_CHALLENGE = bytesToB64url(new Uint8Array(32).fill(9));
/** The start answer's `options` as the server sends them (webauthn-rs: `{publicKey: …}`). */
const OPTIONS = {
  publicKey: {
    challenge: CHALLENGE,
    timeout: 60000,
    rpId: "vault.example.com",
    allowCredentials: [{ type: "public-key", id: "AAEC" }],
    userVerification: "preferred",
  },
};
const KEY_PAGE = "https://vault.example.com/two-step/key";
const SERVER = "https://vault.example.com";
const HOST = "vault.example.com";
const STATE = bytesToB64url(new Uint8Array(16).fill(5));
const OTHER_STATE = bytesToB64url(new Uint8Array(16).fill(6));

/** An assertion as the key page hands it back, signed over `challenge` (only clientDataJSON matters here). */
function assertion(challenge = CHALLENGE, type = "webauthn.get") {
  const clientData = jsonToB64url({ type, challenge, origin: "https://vault.example.com", crossOrigin: false });
  return {
    id: "AAEC",
    rawId: "AAEC",
    type: "public-key",
    response: { clientDataJSON: clientData, authenticatorData: "AA", signature: "AA", userHandle: null },
    clientExtensionResults: {},
  };
}

const fragment = (params: Record<string, string>) => "#" + new URLSearchParams(params);

describe("base64url", () => {
  it("round-trips bytes and JSON (UTF-8)", () => {
    const bytes = new Uint8Array([0, 251, 255, 62, 63, 1]);
    expect(b64urlToBytes(bytesToB64url(bytes))).toEqual(bytes);
    expect(bytesToB64url(bytes)).not.toMatch(/[+/=]/);
    const json = jsonToB64url({ name: "Schlüssel ✓" });
    expect(JSON.parse(new TextDecoder().decode(b64urlToBytes(json)!))).toEqual({ name: "Schlüssel ✓" });
  });
  it("refuses padding, other alphabets and impossible lengths", () => {
    expect(b64urlToBytes("AA==")).toBeNull();
    expect(b64urlToBytes("A+/B")).toBeNull();
    expect(b64urlToBytes("AAAAA")).toBeNull();
  });
});

describe("the app opens the key page", () => {
  it("builds <key_page>#v=1&options=…&return=…&state=… with the options exactly as the server sent them", () => {
    const { url, state } = keyPageUrl(KEY_PAGE, OPTIONS, "app", SERVER)!;
    expect(url.startsWith(`${KEY_PAGE}#`)).toBe(true);
    const params = new URLSearchParams(url.split("#")[1]);
    expect([...params.keys()]).toEqual(["v", "options", "return", "state"]);
    expect(params.get("v")).toBe("1");
    expect(params.get("return")).toBe("app");
    expect(params.get("state")).toBe(state);
    expect(JSON.parse(new TextDecoder().decode(b64urlToBytes(params.get("options")!)!))).toEqual(OPTIONS);
    expect(keyPageUrl(KEY_PAGE, OPTIONS, "page", SERVER)!.url).toMatch(/&return=page&state=/);
  });
  it("a fresh 16-byte random state for every hand-off", () => {
    const a = keyPageUrl(KEY_PAGE, OPTIONS, "app", SERVER)!.state;
    const b = keyPageUrl(KEY_PAGE, OPTIONS, "app", SERVER)!.state;
    expect(a).not.toBe(b);
    expect(validState(a)).toBe(true);
    expect(b64urlToBytes(a)!.length).toBe(16);
  });
  it("accepts the bare publicKey object too", () => {
    expect(keyPageUrl(KEY_PAGE, OPTIONS.publicKey, "app", SERVER)).not.toBeNull();
  });
  it("opens nothing unless the page is https on exactly the relying party's host", () => {
    expect(keyPageUrl("http://vault.example.com/two-step/key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("https://evil.example/two-step/key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("https://sub.vault.example.com/two-step/key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("https://example.com/two-step/key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("https://user:pw@vault.example.com/two-step/key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("passauth://two-step-key", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl("not a url", OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl(undefined, OPTIONS, "app", SERVER)).toBeNull();
    expect(keyPageUrl(KEY_PAGE, { publicKey: { ...OPTIONS.publicKey, rpId: undefined } }, "app", SERVER)).toBeNull();
    expect(keyPageUrl(KEY_PAGE, { publicKey: { rpId: "vault.example.com" } }, "app", SERVER)).toBeNull();
  });
  it("opens nothing unless the page is on the server the app is signing in to (host, any case/port)", () => {
    const evilOptions = { publicKey: { ...OPTIONS.publicKey, rpId: "evil.example" } };
    expect(keyPageUrl("https://evil.example/two-step/key", evilOptions, "app", SERVER)).toBeNull();
    expect(keyPageUrl(KEY_PAGE, OPTIONS, "app", "https://other.example.com")).toBeNull();
    expect(keyPageUrl(KEY_PAGE, OPTIONS, "app", "not a url")).toBeNull();
    expect(keyPageUrl(KEY_PAGE, OPTIONS, "app", "https://VAULT.example.com:8443")).not.toBeNull();
  });
  it("drops a fragment the server put on the page address", () => {
    expect(keyPageUrl(`${KEY_PAGE}#return=evil`, OPTIONS, "app", SERVER)!.url.split("#").length).toBe(2);
  });
});

describe("the key page reads its fragment", () => {
  const good = { v: "1", options: jsonToB64url(OPTIONS), return: "app", state: STATE };
  const parse = (hash: string) => parseKeyPageFragment(hash, HOST);

  it("returns the options, the return kind and the state", () => {
    expect(parse(fragment(good))).toEqual({ options: OPTIONS, ret: "app", state: STATE });
    expect(parse(fragment({ ...good, return: "page" }))?.ret).toBe("page");
    // What the app builds, read back.
    const built = keyPageUrl(KEY_PAGE, OPTIONS, "page", SERVER)!;
    expect(parse(built.url.slice(built.url.indexOf("#")))).toEqual({ options: OPTIONS, ret: "page", state: built.state });
  });
  it("wraps bare publicKey options", () => {
    expect(parse(fragment({ ...good, options: jsonToB64url(OPTIONS.publicKey) }))?.options).toEqual(OPTIONS);
  });
  it("needs a state of 22–64 base64url characters", () => {
    const { state: _, ...noState } = good;
    expect(parse(fragment(noState))).toBeNull();
    for (const state of ["short", "a".repeat(65), `${"a".repeat(21)}=`, `${"a".repeat(21)}+`]) expect(parse(fragment({ ...good, state }))).toBeNull();
    expect(parse(fragment({ ...good, state: "a".repeat(64) }))?.state).toBe("a".repeat(64));
    expect(parse(`${fragment(good)}&state=${OTHER_STATE}`)).toBeNull();
  });
  it("passes on only allowlisted request fields: extensions and the rest are dropped", () => {
    const raw = {
      ...OPTIONS.publicKey,
      extensions: { appid: "https://evil.example", prf: { eval: { first: "AAAA" } } },
      hints: ["client-device"],
      mediation: "conditional",
      allowCredentials: [{ type: "public-key", id: "AAEC", transports: ["usb", "nfc"], extra: 1 }],
    };
    const got = parse(fragment({ ...good, options: jsonToB64url({ publicKey: raw }) }))!;
    expect(got.options.publicKey).toEqual({
      challenge: CHALLENGE,
      rpId: HOST,
      allowCredentials: [{ type: "public-key", id: "AAEC", transports: ["usb", "nfc"] }],
      timeout: 60000,
      userVerification: "preferred",
    });
  });
  it("refuses requests for another relying party, without keys, or with malformed fields", () => {
    const bad = (pk: Record<string, unknown>) => parse(fragment({ ...good, options: jsonToB64url({ publicKey: { ...OPTIONS.publicKey, ...pk } }) }));
    expect(bad({ rpId: "evil.example" })).toBeNull();
    expect(bad({ rpId: undefined })).toBeNull();
    expect(bad({ allowCredentials: [] })).toBeNull();
    expect(bad({ allowCredentials: undefined })).toBeNull();
    expect(bad({ allowCredentials: [{ type: "password", id: "AAEC" }] })).toBeNull();
    expect(bad({ allowCredentials: [{ type: "public-key", id: "A+B/" }] })).toBeNull();
    expect(bad({ allowCredentials: [{ type: "public-key", id: "AAEC", transports: "usb" }] })).toBeNull();
    expect(bad({ timeout: "60000" })).toBeNull();
    expect(bad({ userVerification: "always" })).toBeNull();
    expect(bad({ challenge: "" })).toBeNull();
    expect(allowedRequest(OPTIONS.publicKey, "VAULT.example.com")).not.toBeNull();
  });
  it("refuses any return off the fixed list: no URL from the fragment is ever followed", () => {
    for (const ret of ["https://evil.example/", "passauth://two-step-key", "APP", "", "done"]) {
      expect(parse(fragment({ ...good, return: ret }))).toBeNull();
    }
  });
  it("refuses missing, repeated, damaged or other-version parts", () => {
    expect(parse("")).toBeNull();
    expect(parse("#")).toBeNull();
    expect(parse(fragment({ ...good, v: "2" }))).toBeNull();
    expect(parse(fragment({ options: good.options, return: "app", state: STATE }))).toBeNull();
    expect(parse(fragment({ v: "1", return: "app", state: STATE }))).toBeNull();
    expect(parse(fragment({ v: "1", options: good.options, state: STATE }))).toBeNull();
    expect(parse(`${fragment(good)}&return=page`)).toBeNull();
    expect(parse(fragment({ ...good, options: "%%%" }))).toBeNull();
    expect(parse(fragment({ ...good, options: jsonToB64url([1, 2]) }))).toBeNull();
    expect(parse(fragment({ ...good, options: jsonToB64url({ publicKey: { rpId: "x" } }) }))).toBeNull();
    expect(parse(fragment({ ...good, options: bytesToB64url(new TextEncoder().encode("{not json")) }))).toBeNull();
    expect(parse(`#${"a".repeat(40_000)}`)).toBeNull();
  });
  it("knows its own paths", () => {
    expect(isKeyPagePath("/two-step/key")).toBe(true);
    expect(isKeyPagePath("/two-step/key/")).toBe(true);
    expect(isKeyPagePath(KEY_DONE_PATH)).toBe(true);
    expect(isKeyPagePath("/two-step")).toBe(false);
    expect(isKeyPagePath("/two-step/key/other")).toBe(false);
  });
});

describe("the key page hands the answer back", () => {
  it("encodes the credential for a fixed target only", () => {
    const cred = assertion();
    const app = returnTarget("app", "https://vault.example.com", STATE, { credential: cred });
    expect(app.startsWith(`${APP_RETURN}#v=1&state=${STATE}&credential=`)).toBe(true);
    expect(parseReturnFragment(app.slice(app.indexOf("#")))).toEqual({ credential: cred, state: STATE });
    const page = returnTarget("page", "https://vault.example.com", STATE, { cancelled: true });
    expect(page).toBe(`https://vault.example.com${KEY_DONE_PATH}#v=1&state=${STATE}&error=cancelled`);
    expect(parseReturnFragment(page.slice(page.indexOf("#")))).toEqual({ cancelled: true, state: STATE });
  });
  it("the app refuses anything else", () => {
    const st = `state=${STATE}`;
    expect(parseReturnFragment(`#v=1&${st}`)).toBeNull();
    expect(parseReturnFragment(`#v=2&${st}&error=cancelled`)).toBeNull();
    expect(parseReturnFragment(`#v=1&${st}&error=other`)).toBeNull();
    expect(parseReturnFragment(`#v=1&${st}&error=cancelled&credential=${jsonToB64url(assertion())}`)).toBeNull();
    expect(parseReturnFragment(`#v=1&${st}&credential=%%%`)).toBeNull();
    expect(parseReturnFragment("#v=1&error=cancelled")).toBeNull();
    expect(parseReturnFragment(`#v=1&state=bad&error=cancelled`)).toBeNull();
  });
});

describe("the app's waiter", () => {
  const ok = (cred = assertion(), state = STATE) => returnTarget("app", "https://vault.example.com", state, { credential: cred });
  const cancel = (state = STATE) => returnTarget("app", "https://vault.example.com", state, { cancelled: true });

  it("takes this start's credential once", async () => {
    const w = new KeyPageWaiter();
    const answer = w.expect(OPTIONS, STATE);
    expect(w.isWaiting).toBe(true);
    expect(w.deliver(ok())).toBe(true);
    expect(await answer).toEqual(assertion());
    expect(w.isWaiting).toBe(false);
    expect(w.deliver(ok())).toBe(false);
  });
  it("takes a result (credential or cancel) only with the state it opened; the wait goes on", async () => {
    const w = new KeyPageWaiter();
    const answer = w.expect(OPTIONS, STATE);
    expect(w.deliver(cancel(OTHER_STATE))).toBe(false);
    expect(w.deliver(ok(assertion(), OTHER_STATE))).toBe(false);
    expect(w.deliver(`${APP_RETURN}#v=1&error=cancelled`)).toBe(false);
    expect(w.deliver(`${APP_RETURN}#v=1&credential=${jsonToB64url(assertion())}`)).toBe(false);
    expect(w.deliver(`${APP_RETURN}#v=1&state=${STATE}&error=cancelledx`)).toBe(false);
    expect(w.isWaiting).toBe(true);
    expect(w.deliver(ok())).toBe(true);
    expect(await answer).toEqual(assertion());
  });
  it("ignores results while nothing waits", () => {
    expect(new KeyPageWaiter().deliver(ok())).toBe(false);
  });
  it("ignores a credential for another challenge, another ceremony type, or another address", async () => {
    const w = new KeyPageWaiter();
    const answer = w.expect(OPTIONS, STATE);
    expect(w.deliver(ok(assertion(OTHER_CHALLENGE)))).toBe(false);
    expect(w.deliver(ok(assertion(CHALLENGE, "webauthn.create")))).toBe(false);
    expect(w.deliver(ok().replace(APP_RETURN, "passauth://other"))).toBe(false);
    expect(w.deliver(ok().replace(APP_RETURN, "otpauth://two-step-key"))).toBe(false);
    expect(w.deliver(`${APP_RETURN}#v=1&credential=${jsonToB64url({ response: {} })}`)).toBe(false);
    expect(w.isWaiting).toBe(true);
    expect(w.deliver(ok())).toBe(true);
    expect(await answer).not.toBeNull();
  });
  it("cancelled on the page or in the app = null", async () => {
    const w = new KeyPageWaiter();
    const first = w.expect(OPTIONS, STATE);
    expect(w.deliver(cancel())).toBe(true);
    expect(await first).toBeNull();
    const second = w.expect(OPTIONS, STATE);
    w.cancel();
    expect(await second).toBeNull();
  });
  it("a new start ends the one before it", async () => {
    const w = new KeyPageWaiter();
    const first = w.expect(OPTIONS, STATE);
    const second = w.expect({ publicKey: { ...OPTIONS.publicKey, challenge: OTHER_CHALLENGE } }, OTHER_STATE);
    expect(await first).toBeNull();
    expect(w.deliver(ok())).toBe(false);
    expect(w.deliver(ok(assertion(OTHER_CHALLENGE)))).toBe(false);
    expect(w.deliver(ok(assertion(OTHER_CHALLENGE), OTHER_STATE))).toBe(true);
    expect(await second).not.toBeNull();
  });
  it("reads results at the extension's done page with its base", async () => {
    const w = new KeyPageWaiter();
    const base = `https://vault.example.com${KEY_DONE_PATH}`;
    const answer = w.expect(OPTIONS, STATE);
    const url = returnTarget("page", "https://vault.example.com", STATE, { credential: assertion() });
    expect(w.deliver(url)).toBe(false);
    expect(w.deliver(url, base)).toBe(true);
    expect(await answer).toEqual(assertion());
  });
  it("refuses options without a challenge", async () => {
    await expect(new KeyPageWaiter().expect({ publicKey: {} }, STATE)).rejects.toThrow();
    await expect(new KeyPageWaiter().expect(OPTIONS, "short")).rejects.toThrow();
  });
  it("challengeOf decodes the options' challenge", () => {
    expect(challengeOf(OPTIONS)).toEqual(b64urlToBytes(CHALLENGE));
  });
});

describe("sign-in context", () => {
  it("reads the server's answer, dropping anything else and control characters", () => {
    expect(readContext({ client: "android", device_name: "Pixel\u202e 9", ip: "203.0.113.5", started_at: 1000, email: "a@b.c" })).toEqual({
      client: "android",
      deviceName: "Pixel 9",
      ip: "203.0.113.5",
      startedAt: 1000,
    });
    expect(readContext({ client: null, device_name: null, ip: null, started_at: 5 })).toEqual({ client: null, deviceName: null, ip: null, startedAt: 5 });
    expect(readContext({ client: "web" })).toBeNull();
    expect(readContext([])).toBeNull();
    expect(readContext(null)).toBeNull();
  });
  it("names the device, else the app, with the address and how long ago", () => {
    const at = (c: Partial<{ client: string | null; deviceName: string | null; ip: string | null }>, ago: number) =>
      contextLine({ client: null, deviceName: null, ip: "203.0.113.5", startedAt: 1000, ...c }, 1000 + ago);
    expect(at({ deviceName: "Alex's Pixel", client: "android" }, 5)).toBe("Signing in on Alex's Pixel from 203.0.113.5, 5 seconds ago.");
    expect(at({ client: "android" }, 90)).toBe("Signing in on PassAuth for Android from 203.0.113.5, 2 minutes ago.");
    expect(at({ client: "ios" }, 60)).toBe("Signing in on PassAuth for iPhone from 203.0.113.5, 1 minute ago.");
    expect(at({ client: "extension" }, 0)).toContain("PassAuth extension");
    expect(at({ client: "desktop" }, 0)).toContain("PassAuth desktop app");
    expect(at({ client: "web" }, 0)).toContain("web vault");
    expect(at({ client: "something" }, 0)).toContain("an unknown app");
    expect(at({ client: "web", ip: null }, 0)).toBe("Signing in on web vault, 1 second ago.");
  });
  it("asks the page's own server, and treats 404 or a network error as ended", async () => {
    const calls: string[] = [];
    const answer = (status: number, body: unknown) =>
      (async (url: string) => {
        calls.push(url);
        return new Response(JSON.stringify(body), { status });
      }) as unknown as typeof fetch;
    expect(await fetchContext(CHALLENGE, answer(200, { client: "web", device_name: null, ip: "::1", started_at: 1 }))).toEqual({ client: "web", deviceName: null, ip: "::1", startedAt: 1 });
    expect(calls[0]).toBe(`/api/auth/2fa/passkey/context?challenge=${CHALLENGE}`);
    expect(await fetchContext(CHALLENGE, answer(404, { error: "not_found" }))).toBeNull();
    expect(await fetchContext(CHALLENGE, answer(429, { error: "rate_limited" }))).toBeNull();
    expect(await fetchContext(CHALLENGE, (async () => { throw new TypeError("Failed to fetch"); }) as unknown as typeof fetch)).toBeNull();
    expect(CONTEXT_ENDED).toMatch(/has ended/);
  });
});
