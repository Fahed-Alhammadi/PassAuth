// Passkey requests (background/passkey-handler.ts) with the vault mocked: S4 (user verification is real), C18
// (a request belongs to the account unlocked when it came, at most 4 minutes), S16 (new logins are named after
// the host, not the page's rp.name), S12 (page-supplied names are capped), L-3 (a tab whose user cancelled gets no
// window again without a fresh user gesture, for a while).

import { beforeEach, expect, test, vi } from "vitest";
import { b64uEncode } from "../src/background/passkeys";
import { codeOf, PASSWORD_REQUIRED } from "../src/shared/errors";
import type { CreateRequest, GetRequest, PasskeyRuntimeReply } from "../src/shared/passkey-types";
import { installedChrome } from "./chrome";
import { fromB64u } from "./helpers";

const v = vi.hoisted(() => {
  const data = { verified: false, generation: 1, created: [] as any[], quota: false, entries: [] as any[] };
  return {
    data,
    ensureUnlocked: async () => true,
    allEntries: () => data.entries,
    getEntry: () => undefined,
    canWrite: () => true,
    isPersonal: () => true,
    vaultName: () => "Personal",
    owner: () => ({ id: "a1", generation: data.generation }),
    stillOwner: (o: { generation: number }) => o.generation === data.generation,
    recentlyVerified: async () => data.verified,
    passkeyVerified: async () => data.verified,
    verifyMasterPassword: async (password: string) => {
      if (password !== "pw") throw new Error("Wrong master password or Secret Key.");
      data.verified = true;
    },
    createItem: async (item: any) => {
      // The server's storage limit (403 quota_exceeded), as api.ts words it.
      if (data.quota) throw Object.assign(new Error("You've reached this server's storage limit. Delete items or ask the server's admin."), { code: "quota_exceeded" });
      data.created.push(item);
      return "id";
    },
    updateItem: async () => {},
  };
});
vi.mock("../src/background/vault", () => v);
const w = vi.hoisted(() => ({ opened: [] as string[] }));
vi.mock("../src/shared/windows", () => ({
  openCentered: async (url: string) => {
    w.opened.push(url);
    return { id: 77 };
  },
}));

const { BACKOFF_MS, backedOff, cancelPasskey, cancelPasskeysInTab, decide, handlePasskey, pendingRequest, timeoutOf, MAX_TIMEOUT_MS } = await import("../src/background/passkey-handler");

const ORIGIN = "https://login.example.com";
const createOptions = (uv?: string, extra: Record<string, unknown> = {}) => ({
  rp: { id: "example.com", name: "Example Corp" },
  user: { id: b64uEncode(new TextEncoder().encode("user-1")), name: "alex@example.com", displayName: "Alex" },
  challenge: b64uEncode(crypto.getRandomValues(new Uint8Array(32))),
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  ...(uv ? { authenticatorSelection: { userVerification: uv } } : {}),
  ...extra,
});

let tab = 100;
/** Start a creation request; resolves once its window "opened" with the request id. */
async function start(options: Record<string, unknown>, origin = ORIGIN) {
  const before = w.opened.length;
  // Whatever a page sends: the handler checks it.
  const reply = handlePasskey({ type: "passkey:create", options: options as unknown as CreateRequest, origin, topLevel: true, tabId: ++tab, frameId: 0, bridgeId: "b", activated: true });
  for (let i = 0; i < 50 && w.opened.length === before; i++) await new Promise((r) => setTimeout(r, 1));
  const id = /#passkey=(.+)$/.exec(w.opened.at(-1)!)![1]!;
  return { id, reply };
}

const flags = (reply: PasskeyRuntimeReply) => {
  if (!("result" in reply)) throw new Error(`no result: ${JSON.stringify(reply)}`);
  return fromB64u(reply.result.response.authenticatorData)[32] ?? 0;
};
const UV = 0x04;

beforeEach(() => {
  v.data.verified = false;
  v.data.generation = 1;
  v.data.created = [];
  v.data.quota = false;
  v.data.entries = [];
});

test("a passkey the server's storage limit refuses: the site gets an error, the page a plain note naming no vault data", async () => {
  const fake = installedChrome();
  fake.sentToTabs.length = 0;
  v.data.quota = true;
  const { id, reply } = await start(createOptions());
  await decide(id, true, "new");
  expect("error" in (await reply)).toBe(true);
  expect(v.data.created).toHaveLength(0);
  expect(fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => [s.tabId, s.message.text])).toStrictEqual([
    [tab, "PassAuth couldn't save the passkey. You've reached this server's storage limit. Delete items or ask the server's admin."],
  ]);
});

test("S4 required, master password not entered recently: the window asks, it is checked, UV is set", async () => {
  const { id, reply } = await start(createOptions("required"));
  expect((await pendingRequest(id))?.needsPassword).toBe(true);
  // Accepting without the password: asked for it.
  const e = await decide(id, true, "new").catch((err) => err);
  expect(codeOf(e)).toBe(PASSWORD_REQUIRED);
  await expect(decide(id, true, "new", false, "wrong")).rejects.toThrow("Wrong master password or Secret Key.");
  await decide(id, true, "new", false, "pw");
  expect(flags(await reply) & UV).toBe(UV);
});

test("S4 required, entered recently: no prompt, UV set", async () => {
  v.data.verified = true;
  const { id, reply } = await start(createOptions("required"));
  expect((await pendingRequest(id))?.needsPassword).toBe(false);
  await decide(id, true, "new");
  expect(flags(await reply) & UV).toBe(UV);
});

test("S4 required, the few minutes run out while the window is open: asked then", async () => {
  v.data.verified = true;
  const { id, reply } = await start(createOptions("required"));
  v.data.verified = false;
  expect(codeOf(await decide(id, true, "new").catch((err) => err))).toBe(PASSWORD_REQUIRED);
  expect((await pendingRequest(id))?.needsPassword).toBe(true);
  await decide(id, true, "new", false, "pw");
  expect(flags(await reply) & UV).toBe(UV);
});

test("S4 preferred (and missing): UV only when the password was entered recently", async () => {
  for (const uv of ["preferred", undefined]) {
    v.data.verified = false;
    let { id, reply } = await start(createOptions(uv));
    expect((await pendingRequest(id))?.needsPassword).toBe(false);
    await decide(id, true, "new");
    expect(flags(await reply) & UV, `${uv} not verified`).toBe(0);
    v.data.verified = true;
    ({ id, reply } = await start(createOptions(uv)));
    await decide(id, true, "new");
    expect(flags(await reply) & UV, `${uv} verified`).toBe(UV);
  }
});

test("S4 discouraged: never UV", async () => {
  v.data.verified = true;
  const { id, reply } = await start(createOptions("discouraged"));
  await decide(id, true, "new");
  expect(flags(await reply) & UV).toBe(0);
});

test("C18: locked or switched while the window was open → nothing is created or saved", async () => {
  const { id, reply } = await start(createOptions());
  v.data.generation = 2; // lock / account switch
  await decide(id, true, "new");
  expect(await reply).toMatchObject({ error: { name: "NotAllowedError" } });
  expect(v.data.created).toHaveLength(0);
});

test("C18: the window waits for the page's timeout, at most 4 minutes", () => {
  expect(MAX_TIMEOUT_MS).toBe(240_000);
  expect(timeoutOf({ timeout: 600_000 })).toBe(240_000);
  expect(timeoutOf({ timeout: 60_000 })).toBe(60_000);
  expect(timeoutOf({ timeout: 1 })).toBe(10_000);
  expect(timeoutOf({})).toBe(120_000);
});

test("S16: a new login for a passkey is named after the host, never after the page's rp.name", async () => {
  for (const [origin, name] of [
    ["https://login.example.com", "login.example.com"],
    ["https://www.example.com", "example.com"],
  ]) {
    const { id, reply } = await start(createOptions(undefined, { rp: { id: "example.com", name: "Your Bank — sign in" } }), origin);
    await decide(id, true, "new");
    await reply;
    expect(v.data.created.at(-1).name).toBe(name);
    expect(v.data.created.at(-1).login.urls).toStrictEqual([{ url: origin, match: "default" }]);
  }
});

test("S12: page-supplied passkey names are cut to 256 characters before they are stored", async () => {
  const long = "x".repeat(5000);
  const { id, reply } = await start(createOptions(undefined, { rp: { id: "example.com", name: long }, user: { id: b64uEncode(new Uint8Array([1])), name: long, displayName: long } }));
  expect((await pendingRequest(id))?.userName.length).toBeLessThanOrEqual(64);
  await decide(id, true, "new");
  await reply;
  const passkey = v.data.created.at(-1).login.passkeys[0];
  expect([passkey.rp_name.length, passkey.user_name.length, passkey.user_display_name.length]).toStrictEqual([256, 256, 256]);
});

test("a request left by a page that has gone (reload, navigation) doesn't block its tab; closing the tab ends its request", async () => {
  // Found in a real browser: after a reload, "Another passkey request is already open in this tab" until the old
  // window (hidden behind the browser) timed out.
  const t = ++tab;
  const ask = (documentId: string) =>
    handlePasskey({ type: "passkey:create", options: createOptions() as unknown as CreateRequest, origin: ORIGIN, topLevel: true, tabId: t, frameId: 0, bridgeId: "b", documentId, activated: true });
  const opened = async (before: number) => {
    for (let i = 0; i < 50 && w.opened.length === before; i++) await new Promise((r) => setTimeout(r, 1));
    return /#passkey=(.+)$/.exec(w.opened.at(-1)!)![1]!;
  };
  let before = w.opened.length;
  const first = ask("doc-1");
  const firstId = await opened(before);
  // The same page asking again while its window is open: refused.
  expect(await ask("doc-1")).toStrictEqual({ error: { name: "NotAllowedError", message: "Another passkey request is already open in this tab." } });
  // The tab now shows another document: the old request ends (its window closes) and the new one opens.
  before = w.opened.length;
  const second = ask("doc-2");
  expect(await first).toStrictEqual({ error: { name: "NotAllowedError", message: "The request was cancelled." } });
  expect(await pendingRequest(firstId)).toBeNull();
  const secondId = await opened(before);
  expect(await pendingRequest(secondId)).not.toBeNull();
  cancelPasskeysInTab(t);
  expect(await second).toStrictEqual({ error: { name: "NotAllowedError", message: "The request was cancelled." } });
  expect(await pendingRequest(secondId)).toBeNull();
});

// ------------------------------------------------------------------ L-3: no window again and again

/** A sign-in request from tab `t` (with or without a user gesture just before); resolves with the window's id, or null when none opened. */
async function signIn(t: number, activated: boolean, bridgeId = "g") {
  const before = w.opened.length;
  const options = { challenge: b64uEncode(crypto.getRandomValues(new Uint8Array(32))), rpId: "example.com" } as unknown as GetRequest;
  const reply = handlePasskey({ type: "passkey:get", options, origin: ORIGIN, topLevel: true, tabId: t, frameId: 0, bridgeId, activated });
  let settled = false;
  void reply.then(() => (settled = true));
  for (let i = 0; i < 50 && w.opened.length === before && !settled; i++) await new Promise((r) => setTimeout(r, 1));
  return { reply, id: w.opened.length > before ? /#passkey=(.+)$/.exec(w.opened.at(-1)!)![1]! : null };
}

/** A passkey for example.com, created the normal way, in the vault. */
async function withPasskey() {
  const { id, reply } = await start(createOptions());
  await decide(id, true, "new");
  await reply;
  v.data.entries = [{ id: "e1", item: v.data.created.at(-1), vaultId: "v-own", revision: 1, enc: {} }];
}

const CANCELLED = { error: { name: "NotAllowedError", message: "The request was cancelled." } };

test("L-3: after the user cancels, the tab's sign-in requests without a fresh gesture are refused at once, for a while", async () => {
  await withPasskey();
  const t = ++tab;
  // A two-step page asks as it loads (no gesture): the window opens; the user cancels.
  let r = await signIn(t, false);
  expect(r.id).not.toBeNull();
  await decide(r.id!, false);
  expect(await r.reply).toStrictEqual(CANCELLED);
  expect(backedOff(t)).toBe(true);
  // The page asks again at once, and again: no window.
  for (const _ of [1, 2]) {
    r = await signIn(t, false);
    expect(r.id).toBeNull();
    expect(await r.reply).toStrictEqual(CANCELLED);
  }
  // Another tab isn't held back.
  expect(backedOff(t + 1)).toBe(false);
  // With a click or key press just before (the user asked again), the window opens; this time the user signs in.
  r = await signIn(t, true);
  expect(r.id).not.toBeNull();
  await decide(r.id!, true, "e1");
  expect("result" in (await r.reply)).toBe(true);
  // That clears the hold.
  expect(backedOff(t)).toBe(false);
});

test("L-3: the hold doubles with every cancel (30 s, 60 s, …, at most 10 minutes) and ends by itself", async () => {
  await withPasskey();
  const t = ++tab;
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    vi.setSystemTime(1_000_000);
    let r = await signIn(t, true);
    await decide(r.id!, false);
    await r.reply;
    vi.setSystemTime(1_000_000 + BACKOFF_MS - 1);
    expect(backedOff(t)).toBe(true);
    vi.setSystemTime(1_000_000 + BACKOFF_MS + 1);
    expect(backedOff(t)).toBe(false);
    // Asked again after the hold (no gesture), cancelled again: twice as long.
    r = await signIn(t, false);
    expect(r.id).not.toBeNull();
    await decide(r.id!, false);
    await r.reply;
    const second = Date.now();
    vi.setSystemTime(second + 2 * BACKOFF_MS - 1);
    expect(backedOff(t)).toBe(true);
    vi.setSystemTime(second + 2 * BACKOFF_MS + 1);
    expect(backedOff(t)).toBe(false);
  } finally {
    vi.useRealTimers();
  }
});

test("L-3: a page that aborts its own request is held back like a cancel; a page that went away isn't; closing the tab forgets it", async () => {
  await withPasskey();
  const t = ++tab;
  let r = await signIn(t, false, "g1");
  cancelPasskey(t, 0, "g1");
  expect(await r.reply).toStrictEqual(CANCELLED);
  expect(backedOff(t)).toBe(true);
  // A page can't open, abort and reopen the window in a loop.
  expect((await signIn(t, false, "g2")).id).toBeNull();
  cancelPasskeysInTab(t);
  expect(backedOff(t)).toBe(false);
  // The page navigated (pagehide): no hold.
  r = await signIn(t, false, "g3");
  expect(r.id).not.toBeNull();
  cancelPasskey(t, 0, "g3", true);
  await r.reply;
  expect(backedOff(t)).toBe(false);
});

test("the server's key page in PassAuth's security-key window: the browser's own authenticators answer, no PassAuth window", async () => {
  const fake = installedChrome();
  const keyTab = ++tab;
  await fake.session.set({
    twoStepKeyWait: { id: "h1", tabId: keyTab, windowId: 9, done: `${ORIGIN}/two-step/key/done`, challenge: "AAAA", state: "s".repeat(22), purpose: "login" },
  });
  const before = w.opened.length;
  const get = { rpId: "login.example.com", challenge: b64uEncode(crypto.getRandomValues(new Uint8Array(32))), allowCredentials: [] } as unknown as GetRequest;
  expect(await handlePasskey({ type: "passkey:get", options: get, origin: ORIGIN, topLevel: true, tabId: keyTab, frameId: 0, bridgeId: "k", activated: true })).toStrictEqual({ fallback: true });
  expect(
    await handlePasskey({ type: "passkey:create", options: createOptions() as unknown as CreateRequest, origin: ORIGIN, topLevel: true, tabId: keyTab, frameId: 0, bridgeId: "k2", activated: true }),
  ).toStrictEqual({ fallback: true });
  expect(w.opened.length).toBe(before);
  await fake.session.remove("twoStepKeyWait");
});
