// Two-step login with a security key through the server's key page (background/two-step-key.ts): the hand-off state
// machine. A result counts only from the key window's own tab, only on the done page of the key page's origin, only
// once and only for the challenge of the options this worker opened; closing the window is "cancelled"; a worker
// that restarted while waiting closes the window and reports the sign-in as expired.

import { jsonToB64url, KEY_PAGE_MISMATCH } from "@web/lib/key-page";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { installedChrome, resetChrome } from "./chrome";
import { expectReject, toB64u } from "./helpers";

const net = vi.hoisted(() => ({
  start: null as unknown,
  calls: [] as { path: string; body: unknown; accountId?: string }[],
  features: new Set<string>(["two_step_key_page"]),
}));
vi.mock("../src/background/api", () => ({
  api: async (path: string, opts: { body?: unknown; accountId?: string } = {}) => {
    net.calls.push({ path, body: opts.body, ...(opts.accountId ? { accountId: opts.accountId } : {}) });
    if (path === "/auth/2fa/passkey/start") return net.start;
    return { ok: true };
  },
  serverFeatures: async () => net.features,
}));
const win = vi.hoisted(() => ({ opened: [] as string[], removed: [] as number[], seq: 500 }));
vi.mock("../src/shared/windows", () => ({
  openCentered: async (url: string) => {
    win.opened.push(url);
    const id = ++win.seq;
    return { id, tabs: [{ id: id + 1000 }] };
  },
}));

const keys = await import("../src/background/two-step-key");
const { KEY_WAIT_KEY, cancelKeyPage, keySignInStatus, onKeyTabUpdated, onKeyWindowGone, openKeyPage, setKeySignInFinisher, startKeySignIn, EXPIRED_TEXT } = keys;

const fake = installedChrome();
const ORIGIN = "https://vault.example.com";
const challengeBytes = () => crypto.getRandomValues(new Uint8Array(32));

function answer(challenge: Uint8Array, keyPage = `${ORIGIN}/two-step/key`, rpId = "vault.example.com") {
  net.start = { options: { publicKey: { challenge: toB64u(challenge), rpId, allowCredentials: [{ type: "public-key", id: "a2V5" }], userVerification: "preferred" } }, key_page: keyPage };
}

/** An assertion as the key page hands it back, signing `challenge`. */
function credential(challenge: Uint8Array) {
  const clientData = { type: "webauthn.get", challenge: toB64u(challenge), origin: ORIGIN };
  return {
    id: "a2V5",
    rawId: "a2V5",
    type: "public-key",
    response: { clientDataJSON: jsonToB64url(clientData), authenticatorData: "AA", signature: "AA", userHandle: null },
    clientExtensionResults: {},
  };
}
/** The `state` in the fragment of the key page opened last. */
const st = () => new URLSearchParams(new URL(win.opened.at(-1)!).hash.slice(1)).get("state") ?? "";
const doneUrl = (cred: unknown, origin = ORIGIN, state = st()) => `${origin}/two-step/key/done#v=1&state=${state}&credential=${jsonToB64url(cred)}`;
const cancelUrl = (state = st()) => `${ORIGIN}/two-step/key/done#v=1&state=${state}&error=cancelled`;

/** The key window's tab and window ids (as the mocked openCentered made them). */
const opened = () => ({ windowId: win.seq, tabId: win.seq + 1000 });

beforeEach(() => {
  resetChrome(fake);
  fake.local.data.set("accounts", { a1: { server: ORIGIN, email: "alex@example.com", tokens: null } });
  fake.local.data.set("active", "a1");
  keys._restartForTests();
  net.calls = [];
  net.features = new Set(["two_step_key_page"]);
  win.opened = [];
  win.removed = [];
  vi.spyOn(fake.chrome.windows, "remove").mockImplementation((async (id: number) => {
    win.removed.push(id);
  }) as never);
});
afterEach(() => {
  vi.useRealTimers();
});

test("opens the server's key page with the start answer's options in the fragment and return=page", async () => {
  const c = challengeBytes();
  answer(c);
  await openKeyPage("tok-1", "login");
  expect(net.calls).toEqual([{ path: "/auth/2fa/passkey/start", body: { two_factor_token: "tok-1" } }]);
  const url = new URL(win.opened[0]!);
  expect(`${url.origin}${url.pathname}`).toBe(`${ORIGIN}/two-step/key`);
  const params = new URLSearchParams(url.hash.slice(1));
  expect(params.get("v")).toBe("1");
  expect(params.get("return")).toBe("page");
  expect(params.get("options")).toBe(jsonToB64url((net.start as { options: unknown }).options));
  expect([...params.keys()]).toEqual(["v", "options", "return", "state"]);
  // The two-step token never goes into the page's address.
  expect(win.opened[0]).not.toContain("tok-1");
  expect(await keys.isKeyPageRequest({ tabId: opened().tabId, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(true);
});

test("a key page that isn't https on the options' rpId host is refused before anything opens", async () => {
  for (const [page, rp] of [
    ["http://vault.example.com/two-step/key", "vault.example.com"],
    ["https://evil.example.net/two-step/key", "vault.example.com"],
    ["https://sub.vault.example.com/two-step/key", "vault.example.com"],
    ["not a url", "vault.example.com"],
  ] as const) {
    answer(challengeBytes(), page, rp);
    await expectReject(openKeyPage("tok", "login"), (e) => e.message === KEY_PAGE_MISMATCH);
  }
  net.start = { options: { publicKey: { rpId: "vault.example.com" } }, key_page: `${ORIGIN}/two-step/key` };
  await expectReject(openKeyPage("tok", "login"), (e) => e.message === KEY_PAGE_MISMATCH);
  // F2: https on the rpId host, but not the server this account is connected to.
  answer(challengeBytes(), "https://other.example.org/two-step/key", "other.example.org");
  await expectReject(openKeyPage("tok", "login"), (e) => e.message === KEY_PAGE_MISMATCH);
  expect(win.opened).toEqual([]);
  // The same host on another port (and in other letters) is the connected server.
  answer(challengeBytes(), "https://VAULT.example.com:8443/two-step/key", "vault.example.com");
  await openKeyPage("tok", "login");
  expect(win.opened).toHaveLength(1);
  await cancelKeyPage();
});

test("the fragment's state is 16 random bytes, new for every hand-off", async () => {
  answer(challengeBytes());
  await openKeyPage("tok", "login");
  const first = st();
  answer(challengeBytes());
  await openKeyPage("tok", "login");
  expect(first).toMatch(/^[A-Za-z0-9_-]{22}$/);
  expect(st()).toMatch(/^[A-Za-z0-9_-]{22}$/);
  expect(st()).not.toBe(first);
  await cancelKeyPage();
});

test("L5: only the key page itself (its tab, top-level frame, its origin) is left to the browser", async () => {
  answer(challengeBytes());
  await openKeyPage("tok", "login");
  const { tabId } = opened();
  expect(await keys.isKeyPageRequest({ tabId, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(true);
  expect(await keys.isKeyPageRequest({ tabId, frameId: 3, topLevel: false, origin: ORIGIN })).toBe(false);
  expect(await keys.isKeyPageRequest({ tabId, frameId: 0, topLevel: true, origin: "https://evil.example.net" })).toBe(false);
  expect(await keys.isKeyPageRequest({ tabId: tabId + 1, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(false);
  await cancelKeyPage();
  expect(await keys.isKeyPageRequest({ tabId, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(false);
});

test("only the window's own tab, only the done page of that origin, only the right challenge, only once", async () => {
  const c = challengeBytes();
  answer(c);
  const wait = (await openKeyPage("tok", "login")).outcome;
  let outcome: unknown = null;
  void wait.then((o) => {
    outcome = o;
  });
  const { tabId, windowId } = opened();
  // Another tab reaching the done page.
  await onKeyTabUpdated(tabId + 1, { url: doneUrl(credential(c)) });
  // The window's tab on another origin, another path, or with a query.
  await onKeyTabUpdated(tabId, { url: doneUrl(credential(c), "https://evil.example.net") });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key#v=1&credential=${jsonToB64url(credential(c))}` });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key/done?x=1#v=1&state=${st()}&credential=${jsonToB64url(credential(c))}` });
  // A credential for another challenge, a damaged fragment, another version.
  await onKeyTabUpdated(tabId, { url: doneUrl(credential(challengeBytes())) });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key/done#v=1&state=${st()}&credential=%%%` });
  // F1: the right credential with another state, with none, or a cancel with another state or another error.
  await onKeyTabUpdated(tabId, { url: doneUrl(credential(c), ORIGIN, "AAAAAAAAAAAAAAAAAAAAAA") });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key/done#v=1&credential=${jsonToB64url(credential(c))}` });
  await onKeyTabUpdated(tabId, { url: cancelUrl("AAAAAAAAAAAAAAAAAAAAAA") });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key/done#v=1&state=${st()}&error=denied` });
  await onKeyTabUpdated(tabId, { url: `${ORIGIN}/two-step/key/done#v=2&state=${st()}&credential=${jsonToB64url(credential(c))}` });
  await Promise.resolve();
  expect(outcome).toBeNull();
  expect(win.removed).toEqual([]);

  const good = credential(c);
  await onKeyTabUpdated(tabId, { url: doneUrl(good) });
  await vi.waitFor(() => expect(outcome).toEqual({ credential: good }));
  expect(win.removed).toEqual([windowId]);
  expect(fake.session.data.has(KEY_WAIT_KEY)).toBe(false);
  expect(await keys.isKeyPageRequest({ tabId, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(false);
  // Delivered again: nobody waits any more.
  await onKeyTabUpdated(tabId, { url: doneUrl(good) });
  expect(win.removed).toEqual([windowId]);
});

test("Cancel on the page, closing the window or its tab: cancelled", async () => {
  answer(challengeBytes());
  let wait = (await openKeyPage("tok", "login")).outcome;
  await onKeyTabUpdated(opened().tabId, { url: cancelUrl() });
  expect(await wait).toEqual({ cancelled: true });

  answer(challengeBytes());
  wait = (await openKeyPage("tok", "login")).outcome;
  await onKeyWindowGone({ windowId: opened().windowId });
  expect(await wait).toEqual({ cancelled: true });
  // Closed by the user: nothing left to close.
  expect(win.removed).not.toContain(opened().windowId);

  answer(challengeBytes());
  wait = (await openKeyPage("tok", "login")).outcome;
  await onKeyWindowGone({ tabId: opened().tabId });
  expect(await wait).toEqual({ cancelled: true });
  expect(fake.session.data.has(KEY_WAIT_KEY)).toBe(false);
});

test("one hand-off at a time: a new one ends the open one as cancelled and closes its window", async () => {
  answer(challengeBytes());
  const first = (await openKeyPage("tok-1", "login")).outcome;
  const firstWindow = opened().windowId;
  answer(challengeBytes());
  await openKeyPage("tok-2", "login");
  expect(await first).toEqual({ cancelled: true });
  expect(win.removed).toEqual([firstWindow]);
  await cancelKeyPage();
});

test("the window waits at most as long as the server keeps the challenge", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  answer(challengeBytes());
  const wait = (await openKeyPage("tok", "login")).outcome;
  await vi.advanceTimersByTimeAsync(keys.KEY_WAIT_MS + 10);
  expect(await wait).toEqual({ expired: true });
  expect(win.removed).toEqual([opened().windowId]);
});

test("the popup's sign-in: finished in the background with the token and the assertion, status told once", async () => {
  const finished: unknown[] = [];
  setKeySignInFinisher(async (token, cred, remember) => {
    finished.push({ token, cred, remember });
  });
  const c = challengeBytes();
  answer(c);
  const challenge = { token: "tok-9", providers: ["passkey", "recovery"], keyPage: true };
  await startKeySignIn("alex@example.com", challenge, true);
  expect(await keySignInStatus()).toEqual({ status: "waiting", email: "alex@example.com", challenge });
  const good = credential(c);
  await onKeyTabUpdated(opened().tabId, { url: doneUrl(good) });
  await vi.waitFor(() => expect(finished).toEqual([{ token: "tok-9", cred: good, remember: true }]));
  expect(await keySignInStatus()).toBeNull();
});

test("the popup's sign-in: the server's refusal is shown once; Cancel goes back to the choice without an error", async () => {
  setKeySignInFinisher(async () => {
    throw new Error("Security key not recognized.");
  });
  const c = challengeBytes();
  answer(c);
  const challenge = { token: "tok", providers: ["passkey"], keyPage: true };
  await startKeySignIn("alex@example.com", challenge, false);
  await onKeyTabUpdated(opened().tabId, { url: doneUrl(credential(c)) });
  await vi.waitFor(async () => expect(await keySignInStatus()).toEqual({ status: "failed", email: "alex@example.com", challenge, error: "Security key not recognized." }));
  expect(await keySignInStatus()).toBeNull();

  answer(challengeBytes());
  await startKeySignIn("alex@example.com", challenge, false);
  await onKeyWindowGone({ windowId: opened().windowId });
  await vi.waitFor(async () => expect(await keySignInStatus()).toEqual({ status: "cancelled", email: "alex@example.com", challenge }));
});

test("a worker that restarted while waiting: the window closes and the sign-in reports expired", async () => {
  const finished: unknown[] = [];
  setKeySignInFinisher(async (...args) => {
    finished.push(args);
  });
  const c = challengeBytes();
  answer(c);
  await startKeySignIn("alex@example.com", { token: "tok", providers: ["passkey"], keyPage: true }, true);
  const { tabId, windowId } = opened();
  keys._restartForTests();
  // The record of the window survived in session storage: the tab is still known as the key page's.
  expect(await keys.isKeyPageRequest({ tabId, frameId: 0, topLevel: true, origin: ORIGIN })).toBe(true);
  await onKeyTabUpdated(tabId, { url: doneUrl(credential(c)) });
  expect(win.removed).toEqual([windowId]);
  expect(finished).toEqual([]);
  expect(await keySignInStatus()).toEqual({ status: "failed", email: "", error: EXPIRED_TEXT });

  // Or the popup asks first: the left-over window closes then.
  answer(challengeBytes());
  await startKeySignIn("alex@example.com", { token: "tok", providers: ["passkey"], keyPage: true }, true);
  keys._restartForTests();
  expect(await keySignInStatus()).toEqual({ status: "failed", email: "", error: EXPIRED_TEXT });
  expect(win.removed).toContain(opened().windowId);
  expect(fake.session.data.has(KEY_WAIT_KEY)).toBe(false);
});

test("keyPageOffered follows the server's features", async () => {
  await fake.local.set({ accounts: { a1: { server: ORIGIN, email: "alex@example.com", tokens: null } }, active: "a1" });
  expect(await keys.keyPageOffered()).toBe(true);
  net.features = new Set();
  expect(await keys.keyPageOffered()).toBe(false);
});
