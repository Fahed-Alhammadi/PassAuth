// The service worker (background/main.ts → router.ts) with the vault mocked: who may send what (every request type
// against every kind of sender), S2 (what restarts the timeout), S6/S16 (nonces bound to the first frame, the
// menu's unlock needs one, a bad nonce can't close the prompt), S7 (real origins), S8 (fill offers without
// websites, claims checked, secrets to one document), S12 (one session record per pending save, length caps),
// C7 (malformed messages refused), C8 (page text never names vault data), C10 (locked → code).

import type { Item } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { EXTENSION_ID, installedChrome, resetChrome, type SentToTab } from "./chrome";

const v = vi.hoisted(() => {
  type E = { id: string; item: Item; vaultId: string; revision: number; enc: object };
  const data = { unlocked: true, entries: [] as E[], personal: new Set<string>(["v-own"]) };
  const nothing = async () => {};
  return {
    data,
    setLockCheck: () => {},
    setKeysDroppedHandler: () => {},
    setOpenedHandler: () => {},
    setUnlockedHandler: () => {},
    noteReach: () => {},
    isOfflineAlarm: () => false,
    connectionBack: nothing,
    offlineSummary: () => null,
    offlineNotice: () => null,
    offlineMark: () => undefined,
    approveSignIn: async () => ({ approve: true, sealed_key: "s", proof: "p" }),
    finishDeviceSignIn: nothing,
    deviceInfo: async () => ({ id: "d1", name: "PassAuth extension (Chrome)", kind: "extension" }),
    checkForChanges: async () => "ok",
    liveNotice: nothing,
    checkSession: nothing,
    invitations: () => ({ count: 0, key: "" }),
    sharingNotice: () => null,
    rollbackSummary: () => null,
    rolledBack: () => false,
    manifestSummary: () => null,
    manifestWarned: () => false,
    manifestWarning: () => null,
    memoryNotice: () => null,
    notCheckedSummary: () => null,
    otherItems: () => [],
    acceptServerCopy: nothing,
    resetDeviceMemory: nothing,
    serverNeedsUpdate: async () => false,
    sharingIdentity: () => ({ fingerprint: null, paused: false }),
    trustNewKey: nothing,
    vaultTrust: () => ({}),
    ensureUnlocked: async () => data.unlocked,
    unlockedIndex: async () => null,
    allEntries: () => data.entries,
    getEntry: (id: string) => data.entries.find((e) => e.id === id),
    isPersonal: (e: E) => data.personal.has(e.vaultId),
    weakPassword: () => false,
    canWrite: () => true,
    vaultName: (id: string) => (id === "v-own" ? "Personal" : "Team"),
    summarize: (e: E) => ({
      id: e.id,
      name: e.item.name,
      subtitle: e.item.login?.username ?? "",
      host: "",
      url: "",
      folder: "",
      kind: "login",
      favorite: false,
      hasPassword: true,
      hasTotp: false,
      passkeys: 0,
      vaultName: "",
    }),
    totp: () => ({ code: "123456", remaining: 20, period: 30, expires: Date.now() + 20_000 }),
    refreshIfStale: nothing,
    state: async () => ({ status: "unlocked" }),
    setServer: nothing,
    login: async () => ({ done: true }),
    verifyTwoFactor: nothing,
    sendTwoFactorEmail: nothing,
    unlock: nothing,
    sync: nothing,
    generate: async () => "generated",
    createItem: async (..._args: unknown[]): Promise<string> => "new-id",
    updateItem: nothing,
    trashItem: nothing,
    editorInfo: () => ({ vaults: [], defaultVault: "", folders: [] }),
    addAccount: nothing,
    switchAccount: nothing,
    cancelAddAccount: nothing,
    forgetBrowser: nothing,
    setAvatar: nothing,
    removeAvatar: nothing,
    securityKeys: async () => ({ keys: [], methods: [] }),
    removeSecurityKey: async () => ({ keys: [], methods: [] }),
    clearUnlocked: nothing,
    lock: nothing,
    lockAll: nothing,
    logout: nothing,
    logoutAll: nothing,
    anyUnlocked: async () => true,
    persistForNever: nothing,
    owner: () => ({ id: "a1", generation: 1 }),
    stillOwner: () => true,
    recentlyVerified: async () => false,
    passkeyVerified: async () => false,
    verifyMasterPassword: nothing,
    lockStatus: async () => (data.unlocked ? "unlocked" : "locked"),
    wrapForPin: async () => ({ wrapped: {}, base: {}, owner: { id: "a1", generation: 1 } }),
    unlockWithPin: async () => false,
  };
});
vi.mock("../src/background/vault", () => v);

await import("../src/background/main");
const { routes } = await import("../src/background/router");
const fake = installedChrome();

const TAB = { id: 1, url: "https://example.com/login", windowId: 1, active: true };
const popup = { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html` };
type TabLike = { id: number; url: string };
const page = (frameId = 0, origin = "https://example.com", url = `${origin}/login`, tab: TabLike = TAB) => ({
  id: EXTENSION_ID,
  url,
  origin,
  frameId,
  documentId: `doc-${frameId}-${origin}`,
  tab: { id: tab.id, url: tab.url },
});
const framed = (path: "inline-menu.html" | "save-prompt.html", frameId: number, tab: TabLike = TAB) => ({
  id: EXTENSION_ID,
  url: `chrome-extension://${EXTENSION_ID}/${path}`,
  origin: `chrome-extension://${EXTENSION_ID}`,
  frameId,
  documentId: `doc-${path}-${frameId}`,
  tab: { id: tab.id, url: tab.url },
});

const entry = (id: string, url: string, vaultId = "v-own", match: "domain" | "host" | "regex" = "domain") => ({
  id,
  vaultId,
  revision: 1,
  enc: {},
  item: {
    name: id,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: "alex", password: "secret-pw", urls: [{ url, match }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  } satisfies Item,
});

const NOT_ALLOWED = { ok: false, code: "not_allowed", message: "Not allowed." };

beforeEach(async () => {
  resetChrome(fake);
  // No network: /api/config and the like answer "not a PassAuth server".
  vi.stubGlobal("fetch", async () => new Response("", { status: 404 }));
  fake.tabs.set(TAB.id, TAB);
  fake.tabs.set(2, { id: 2, url: "https://example.org/login", windowId: 1 });
  v.data.unlocked = true;
  v.data.entries = [];
  await fake.local.set({
    accounts: { a1: { server: "https://vault.test", email: "alex@example.com", name: "", tokens: { access: "a", refresh: "r" }, lastSync: 0, persistedKeys: null } },
    active: "a1",
  });
});

// First in the file: touch() keeps a 30 s throttle in memory.
test("S2: reading an item and its code never restarts the vault timeout; copying does", async () => {
  v.data.entries = [entry("e1", "https://example.com")];
  v.data.entries[0]!.item.login!.totp = "JBSWY3DPEHPK3PXP";
  for (const msg of [{ type: "state" }, { type: "items" }, { type: "item", id: "e1" }, { type: "totp", id: "e1" }, { type: "passkey:pending", requestId: "x" }]) {
    expect((await fake.deliver(msg, popup)).ok, msg.type).toBe(true);
  }
  expect(fake.alarms.has("autolock")).toBe(false);
  expect((await fake.deliver({ type: "copyField", id: "e1", field: "password" }, popup)).ok).toBe(true);
  expect(fake.alarms.get("autolock")?.delayInMinutes).toBe(15);
});

test("S2: which requests restart the vault timeout (reading never does; unlocking, signing in and settings without the 30 s throttle)", () => {
  const table = routes();
  const activity = (type: string) => table.get(type)?.activity ?? null;
  for (const type of [
    "state",
    "items",
    "item",
    "totp",
    "editorInfo",
    "passkey:pending",
    "securityKeys",
    "lock",
    "logout",
    "setServer",
    "email2fa",
    "twoStepKey:status",
    "twoStepKey:cancel",
    "signInRequests",
    "files:missing",
    "deviceSignIn:start",
    "deviceSignIn:poll",
  ]) {
    expect(activity(type), type).toBe(null);
  }
  for (const type of [
    "fill",
    "copy",
    "copyField",
    "generate",
    "createItem",
    "updateItem",
    "trashItem",
    "sync",
    "neverSave:remove",
    "account:add",
    "account:switch",
    "account:cancelAdd",
    "account:forgetBrowser",
    "avatar:set",
    "avatar:remove",
    "securityKeys:remove",
    "sharing:trust",
    "sharing:accept",
    "manifest:accept",
    "memory:reset",
    "passkey:decide",
    "signInRequests:answer",
    "files:access",
  ]) {
    expect(activity(type), type).toBe("restart");
  }
  for (const type of ["settings", "unlock", "login", "verify2fa", "twoStepKey:start", "deviceSignIn:finish"]) expect(activity(type), type).toBe("force");
  // Requests from pages and frames never count: a fill from the inline menu and a save from the prompt restart it themselves.
  for (const [type, r] of table) if (!r.from.includes("popup")) expect(r.activity, type).toBe(null);
  expect(table.has("no-such-request")).toBe(false);
});

test("regular-expression websites the core refuses: named with its reason on the item page (the editor works it out itself: patternNote)", async () => {
  v.data.entries = [entry("e1", "(?<=a)b", "v-own", "regex")];
  v.data.entries[0]!.item.login!.urls.push({ url: "^https://example\\.com/", match: "regex" }, { url: "(a)\\1", match: "default" });
  const item = await fake.deliver({ type: "item", id: "e1" }, popup);
  expect(item.data.regexErrors).toStrictEqual({ 0: "Look-around is not supported." });
  // "Default" is a pattern too while the user's default is regex.
  await fake.local.set({ settings: { defaultMatch: "regex" } });
  expect((await fake.deliver({ type: "item", id: "e1" }, popup)).data.regexErrors).toStrictEqual({ 0: "Look-around is not supported.", 2: "Backreferences are not supported." });
});

// ------------------------------------------------------------- who may send what

const SENDERS = {
  popup,
  popOut: { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html?popout=1` },
  passkeyWindow: { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html#passkey=req-1` },
  inlineFrame: framed("inline-menu.html", 5),
  saveFrame: framed("save-prompt.html", 7),
  topFrame: page(0),
  sameSiteFrame: page(3, "https://login.example.com"),
  crossSiteFrame: page(4, "https://evil.test"),
  offscreen: { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/offscreen.html` },
} as const;
type SenderName = keyof typeof SENDERS;

const NONCE = "0123456789abcdef";
/** A well-formed example of every request, by channel. */
const REQUESTS: Record<string, Record<string, Record<string, unknown>>> = {
  popup: {
    state: {},
    setServer: { url: "https://vault.test" },
    login: { email: "alex@example.com", password: "pw" },
    verify2fa: { token: "t", provider: "totp", code: "123456", remember: false },
    email2fa: { token: "t" },
    "twoStepKey:start": { email: "alex@example.com", challenge: { token: "t", providers: ["passkey"], keyPage: true }, remember: false },
    "twoStepKey:status": {},
    "twoStepKey:cancel": {},
    unlock: { password: "pw" },
    lock: {},
    logout: {},
    sync: {},
    items: { url: "https://example.com/" },
    item: { id: "e1" },
    totp: { id: "e1" },
    fill: { id: "e1", tabId: 1 },
    generate: { mode: "password" },
    createItem: { item: entry("x", "https://example.com").item },
    updateItem: { id: "e1", item: entry("x", "https://example.com").item },
    "addSite:targets": { url: "https://example.com/" },
    addSite: { id: "e1", url: "https://example.com/" },
    trashItem: { id: "e1" },
    editorInfo: {},
    settings: { patch: { theme: "dark" } },
    "neverSave:remove": { domain: "example.com" },
    copy: { text: "hello" },
    copyField: { id: "e1", field: "password" },
    "account:add": {},
    "account:switch": { id: "a1" },
    "account:cancelAdd": {},
    "account:forgetBrowser": {},
    "avatar:set": { jpeg: "/9j/" },
    "avatar:remove": {},
    securityKeys: {},
    "securityKeys:remove": { id: "k1", password: "pw" },
    "hiddenSites:remove": { domain: "example.com" },
    afterUnlock: {},
    "pin:set": { pin: "123456", password: "pw" },
    "pin:unlock": { pin: "123456" },
    "pin:remove": {},
    sharingIdentity: {},
    "sharing:trust": { userId: "u-2", fingerprint: "F" },
    "sharing:accept": { vaultId: "v1", token: "F" },
    "manifest:accept": { vaultId: "v1" },
    "memory:reset": {},
    policyNotices: {},
    signInRequests: {},
    "signInRequests:answer": { id: "r1", approve: false },
    "deviceSignIn:start": { email: "alex@example.com" },
    "deviceSignIn:create": { account: "a1", body: { email: "alex@example.com", public_key: "k", access_code: "c".repeat(43), device_id: "d", device_name: "n", device_kind: "extension" } },
    "deviceSignIn:poll": { account: "a1", id: "r1", accessCode: "c".repeat(43) },
    "deviceSignIn:verify2fa": { account: "a1", token: "t", provider: "totp", code: "123456", remember: false },
    "deviceSignIn:keyPage": { account: "a1" },
    "deviceSignIn:verifyKey": { account: "a1", token: "t", remember: false },
    "deviceSignIn:finish": { account: "a1", signIn: { email: "alex@example.com", accessToken: "a", refreshToken: "r", bundle: {}, accountId: "acc-1", keys: "AQID" } },
    "deviceSignIn:discard": { account: "a1", accessToken: "a" },
    "files:missing": { id: "e1" },
    "files:access": { itemId: "e1", attachmentId: "f1" },
    "offline:list": {},
    "offline:discard": { itemId: "e1" },
    "offline:conflict": { itemId: "e1" },
    "offline:resolve": { itemId: "e1", choice: "mine" },
  },
  passkeyWindow: { "passkey:pending": { requestId: "r1" }, "passkey:decide": { requestId: "r1", accept: false } },
  inline: {
    "inline:items": { nonce: NONCE },
    "inline:fill": { nonce: NONCE, id: "e1" },
    "inline:close": { nonce: NONCE, refocus: true },
    "inline:return": { nonce: NONCE },
    "inline:touch": { nonce: NONCE },
    "inline:unlock": { nonce: NONCE },
    "inline:generate": { nonce: NONCE },
    "inline:new": { nonce: NONCE },
    "inline:hide": { nonce: NONCE },
  },
  save: {
    "save:offer": { nonce: NONCE },
    "save:answer": { nonce: NONCE, accept: "dismiss", target: "new" },
    "save:resize": { nonce: NONCE, height: 300 },
    "save:touch": { nonce: NONCE },
  },
  content: {
    "page:submitted": { username: "alex", password: "pw", keyboard: true },
    "page:identifier": { username: "alex" },
    "page:formDone": {},
    "page:fillClaim": { token: NONCE },
    "page:inlineInfo": {},
    "page:inlineOpen": { kind: "new-password", username: "alex", minLength: 8, maxLength: 64 },
    "page:contextField": { password: true },
  },
};
/** How the browser's sender information classifies each (senders.ts `senderKind`). */
const KIND = {
  popup: "popup",
  popOut: "popup",
  passkeyWindow: "popup",
  inlineFrame: "inline",
  saveFrame: "save",
  topFrame: "content",
  sameSiteFrame: "content",
  crossSiteFrame: "content",
  offscreen: "offscreen",
} as const satisfies Record<SenderName, string>;

/** Which senders each channel accepts (as before the router existed). */
const ACCEPTS: Record<string, SenderName[]> = {
  popup: ["popup", "popOut", "passkeyWindow"],
  passkeyWindow: ["popup", "popOut", "passkeyWindow"],
  inline: ["inlineFrame"],
  save: ["saveFrame"],
  content: ["topFrame", "sameSiteFrame", "crossSiteFrame"],
};

test("L-5: the worker restricts local storage (tokens, Secret Keys, kept keys) to PassAuth's own pages at start", async () => {
  // Set when main.ts ran (at import above), before any test reset the fake's data.
  await new Promise((r) => setTimeout(r, 0));
  expect((fake.local as unknown as { accessLevel: string }).accessLevel).toBe("TRUSTED_CONTEXTS");
});

test("every request type against every kind of sender: allowed or refused before anything runs", async () => {
  // Locked: no handler gets far, and passkey requests go to the browser at once.
  v.data.unlocked = false;
  const table = routes();
  const all = Object.values(REQUESTS).flatMap((r) => Object.keys(r));
  expect(new Set(all).size, "every request type once").toBe(all.length);
  expect([...table.keys()].sort()).toStrictEqual([...all].sort());
  const outcome = new Map<string, string>();
  for (const [channel, requests] of Object.entries(REQUESTS)) {
    for (const [type, fields] of Object.entries(requests)) {
      for (const [name, sender] of Object.entries(SENDERS) as [SenderName, (typeof SENDERS)[SenderName]][]) {
        const reply = await fake.deliver({ type, ...fields }, sender);
        const refused = reply?.ok === false && reply.code === "not_allowed";
        if (refused) expect(reply, `${type} from ${name}`).toStrictEqual(NOT_ALLOWED);
        const expected = ACCEPTS[channel]!.includes(name) ? "handled" : "refused";
        outcome.set(`${type} from ${name}`, refused ? "refused" : "handled");
        expect(refused ? "refused" : "handled", `${type} from ${name}`).toBe(expected);
        // The router's table says the same.
        expect(table.get(type)?.from.includes(KIND[name]), `${type} from ${name} in the table`).toBe(expected === "handled");
      }
    }
  }
  expect(outcome.size).toBe(all.length * Object.keys(SENDERS).length);
  // Unknown types and anything that isn't a request are refused for everyone.
  for (const sender of Object.values(SENDERS)) {
    expect(await fake.deliver({ type: "no-such-request" }, sender)).toStrictEqual(NOT_ALLOWED);
    expect(await fake.deliver({ type: "toString" }, sender)).toStrictEqual(NOT_ALLOWED);
    expect(await fake.deliver("state", sender)).toStrictEqual(NOT_ALLOWED);
  }
});

test("passkey bridge requests: answered only in a tab's frame (a PassAuth page gets no answer), in the authenticator's shape", async () => {
  v.data.unlocked = false;
  for (const [name, sender] of Object.entries(SENDERS) as [SenderName, (typeof SENDERS)[SenderName]][]) {
    const inTab = "tab" in sender;
    for (const type of ["passkey:create", "passkey:get"]) {
      const reply = await fake.deliver({ type, options: { challenge: "AAAA" }, bridgeId: "b1", origin: "https://forged.test", topLevel: true }, sender);
      // Locked (or not a web origin, or not the top frame): the browser's own authenticators take it.
      expect(reply, `${type} from ${name}`).toStrictEqual(inTab ? { fallback: true } : undefined);
    }
    // A cancel is never answered.
    expect(await fake.deliver({ type: "passkey:cancel", bridgeId: "b1" }, sender), `cancel from ${name}`).toBe(undefined);
  }
  // Options that aren't an object: the browser handles it.
  expect(await fake.deliver({ type: "passkey:get", options: "x", bridgeId: "b1" }, page(0))).toStrictEqual({ fallback: true });
});

test("C7: malformed messages from content scripts and frames are refused before their handler runs", async () => {
  // Work an earlier test started (timeout writes after a refused request) may land late on a slow machine: let it, then start empty.
  await new Promise((r) => setTimeout(r, 100));
  fake.session.data.clear();
  const bad: [Record<string, unknown>, ReturnType<typeof page> | ReturnType<typeof framed>][] = [
    [{ type: "page:submitted", username: 1, password: "pw" }, page(0)],
    [{ type: "page:submitted", username: "alex" }, page(0)],
    [{ type: "page:submitted", username: "alex", password: "p".repeat(64 * 1024 + 1) }, page(0)],
    [{ type: "page:identifier", username: { toString: "x" } }, page(0)],
    [{ type: "page:submitted", username: "alex", password: "pw", keyboard: "yes" }, page(0)],
    [{ type: "page:inlineOpen", kind: "password-manager" }, page(0)],
    [{ type: "page:inlineOpen", maxLength: -1 }, page(0)],
    [{ type: "page:inlineOpen", username: 5 }, page(0)],
    [{ type: "inline:generate", nonce: "short" }, framed("inline-menu.html", 5)],
    [{ type: "inline:hide" }, framed("inline-menu.html", 5)],
    [{ type: "page:fillClaim", token: "../../x" }, page(3)],
    [{ type: "inline:fill", nonce: NONCE, id: 7 }, framed("inline-menu.html", 5)],
    [{ type: "inline:items", nonce: ["x"] }, framed("inline-menu.html", 5)],
    [{ type: "save:answer", nonce: NONCE, accept: "maybe" }, framed("save-prompt.html", 7)],
    [{ type: "save:answer", nonce: NONCE, accept: "save", target: 5 }, framed("save-prompt.html", 7)],
    [{ type: "save:resize", nonce: NONCE, height: "tall" }, framed("save-prompt.html", 7)],
    [{ type: "save:resize", nonce: NONCE, height: Number.NaN }, framed("save-prompt.html", 7)],
    [{ type: "inline:close", nonce: NONCE, refocus: "yes" }, framed("inline-menu.html", 5)],
    [{ type: "inline:return", nonce: 5 }, framed("inline-menu.html", 5)],
    [{ type: "save:touch" }, framed("save-prompt.html", 7)],
  ];
  for (const [msg, sender] of bad) expect(await fake.deliver(msg, sender), JSON.stringify(msg).slice(0, 80)).toStrictEqual(NOT_ALLOWED);
  expect([...fake.session.data.keys()], "nothing was stored").toStrictEqual([]);
});

test('C10: a popup request while locked fails with the code "locked"', async () => {
  v.data.unlocked = false;
  expect(await fake.deliver({ type: "items" }, popup)).toStrictEqual({ ok: false, code: "locked", message: "PassAuth is locked. Unlock it to continue." });
});

test("S12: pending saves of two tabs submitted at the same moment both survive (one record per tab)", async () => {
  const tab2 = { id: 2, url: "https://example.org/login", windowId: 1 };
  const [a, b] = await Promise.all([
    fake.deliver({ type: "page:submitted", username: "alex", password: "pw-1" }, page(0)),
    fake.deliver({ type: "page:submitted", username: "sam", password: "pw-2" }, page(0, "https://example.org", "https://example.org/login", tab2)),
  ]);
  expect([a.data, b.data]).toStrictEqual([true, true]);
  expect([(fake.session.data.get("save:1") as { username: string }).username, (fake.session.data.get("save:2") as { username: string }).username]).toStrictEqual(["alex", "sam"]);
});

test("S12: over-long user names and passwords are not offered (1 KiB / 4 KiB)", async () => {
  expect((await fake.deliver({ type: "page:submitted", username: "a".repeat(1025), password: "pw" }, page(0))).data).toBe(false);
  expect((await fake.deliver({ type: "page:submitted", username: "alex", password: "p".repeat(4097) }, page(0))).data).toBe(false);
  expect((await fake.deliver({ type: "page:submitted", username: "a".repeat(1024), password: "p".repeat(4096) }, page(0))).data).toBe(true);
  // The identifier-first user name too.
  await fake.deliver({ type: "page:identifier", username: "u".repeat(1025) }, page(0));
  expect(fake.session.data.has("user:1")).toBe(false);
  await fake.deliver({ type: "page:identifier", username: "alex" }, page(0));
  expect((fake.session.data.get("user:1") as { username: string }).username).toBe("alex");
});

test('S7: a sandboxed frame (origin "null") on the site\'s URL is not the site', async () => {
  expect((await fake.deliver({ type: "page:submitted", username: "alex", password: "pw" }, { ...page(0), origin: "null" })).data).toBe(false);
  expect(fake.session.data.has("save:1")).toBe(false);
  expect((await fake.deliver({ type: "page:inlineInfo" }, { ...page(3), origin: "null" })).data).toStrictEqual({ mode: "off", status: "locked", count: 0 });
  // A passkey request from it goes to the browser's own authenticators.
  expect(await fake.deliver({ type: "passkey:get", options: { challenge: "AAAA" }, bridgeId: "b" }, { ...page(0), origin: "null" })).toStrictEqual({ fallback: true });
});

test("S8: the fill offer carries no websites; only a frame the login is saved for gets the secrets, at its document", async () => {
  v.data.entries = [entry("e1", "https://login.example.com")];
  const offers: SentToTab[] = [];
  fake.setTabResponder((s) => {
    if (s.message.type === "fill" && s.options?.frameId === 0) return { filled: false };
    if (s.message.type === "fill:offer") {
      offers.push(s);
      const claim = (sender: Record<string, unknown>) => void fake.deliver({ type: "page:fillClaim", token: s.message.token }, sender);
      // A cross-site frame, a sandboxed same-site frame and the real login frame all claim.
      claim(page(3, "https://evil.test"));
      claim({ ...page(4, "https://login.example.com"), origin: "null" });
      setTimeout(() => claim(page(5, "https://login.example.com")), 5);
      return undefined;
    }
    if (s.message.type === "fill") return { filled: true };
    return undefined;
  });
  expect(await fake.deliver({ type: "fill", id: "e1", tabId: 1 }, popup)).toStrictEqual({ ok: true, data: null });
  expect(offers).toHaveLength(1);
  expect(Object.keys(offers[0]!.message).sort()).toStrictEqual(["token", "type"]);
  const secrets = fake.sentToTabs.filter((s) => s.message.type === "fill");
  expect(secrets.map((s) => s.options)).toStrictEqual([{ frameId: 0 }, { documentId: "doc-5-https://login.example.com" }]);
});

test("S8: no frame the login is saved for → nothing is sent", async () => {
  v.data.entries = [entry("e1", "https://login.example.com", "v-own", "host")];
  fake.tabs.set(1, { ...TAB, url: "https://login.example.com/" });
  fake.setTabResponder((s) => {
    if (s.message.type === "fill" && s.options?.frameId === 0) return { filled: false };
    if (s.message.type === "fill:offer")
      void fake.deliver({ type: "page:fillClaim", token: s.message.token }, page(3, "https://ads.example.com", undefined, { ...TAB, url: "https://login.example.com/" }));
    return { filled: true };
  });
  const r = await fake.deliver({ type: "fill", id: "e1", tabId: 1 }, popup);
  expect(r).toMatchObject({ ok: false, code: "cant_fill" });
  expect(fake.sentToTabs.filter((s) => s.message.type === "fill")).toHaveLength(1);
});

test("C8: the keyboard command's note in the page never names the login's websites", async () => {
  v.data.entries = [entry("e1", "https://intranet.example.org/secret-path")];
  // The tab moved on to another site between the shortcut and the fill: fill() refuses, naming the login's websites.
  fake.tabs.set(1, { ...TAB, url: "https://example.com/login" });
  fake.setTabResponder(() => undefined);
  for (const listener of fake.chrome.commands.onCommand.listeners) listener("autofill", { id: 1, url: "https://intranet.example.org/secret-path" });
  const toastsSent = () => fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => s.message.text as string);
  for (let i = 0; i < 100 && !toastsSent().length; i++) await new Promise((r) => setTimeout(r, 5));
  const toasts = toastsSent();
  expect(toasts).toStrictEqual(["This login isn't saved for this site. Open PassAuth to check its websites."]);
  // The popup (PassAuth's own page) does get the reason, with the websites.
  const r = await fake.deliver({ type: "fill", id: "e1", tabId: 1 }, popup);
  expect(r).toStrictEqual({ ok: false, code: "not_for_site", message: "This login is saved for intranet.example.org, not for this site." });
});

test("S13: a shared vault's regular expression doesn't make its login match", async () => {
  v.data.entries = [entry("mine", "^https://example\\.com/", "v-own", "regex"), entry("theirs", "^https://example\\.com/", "v-team", "regex")];
  const r = await fake.deliver({ type: "items", url: "https://example.com/login" }, popup);
  expect(r.data.suggested.map((s: { id: string }) => s.id)).toStrictEqual(["mine"]);
});

test("S6: an inline-menu nonce belongs to the first menu frame that uses it; the menu's unlock needs it and uses it up", async () => {
  v.data.entries = [entry("e1", "https://example.com")];
  const open = await fake.deliver({ type: "page:inlineOpen" }, page(0));
  const nonce = open.data as string;
  expect(nonce).toMatch(/^[\w-]{8,64}$/);
  expect((await fake.deliver({ type: "inline:items", nonce }, framed("inline-menu.html", 5))).ok).toBe(true);
  // Another frame with a copy of the nonce gets nothing.
  expect(await fake.deliver({ type: "inline:items", nonce }, framed("inline-menu.html", 6))).toStrictEqual(NOT_ALLOWED);
  expect(await fake.deliver({ type: "inline:fill", nonce, id: "e1" }, framed("inline-menu.html", 6))).toMatchObject({ ok: false });
  // Without a nonce the menu can't open PassAuth, nor with the popup's own request.
  expect(await fake.deliver({ type: "inline:unlock" }, framed("inline-menu.html", 5))).toStrictEqual(NOT_ALLOWED);
  expect(await fake.deliver({ type: "account:add", nonce }, framed("inline-menu.html", 5))).toStrictEqual(NOT_ALLOWED);
  expect((await fake.deliver({ type: "inline:unlock", nonce }, framed("inline-menu.html", 5))).ok).toBe(true);
  // Used up.
  expect(await fake.deliver({ type: "inline:items", nonce }, framed("inline-menu.html", 5))).toStrictEqual({ ok: false, code: "expired", message: "This menu has expired. Click the field again." });
  // The menu frame never gets the popup's requests.
  expect(await fake.deliver({ type: "state" }, framed("inline-menu.html", 5))).toStrictEqual(NOT_ALLOWED);
});

test("S16: a wrong nonce on the save frame is refused without closing the real prompt; the first frame owns it", async () => {
  expect((await fake.deliver({ type: "page:submitted", username: "alex", password: "pw" }, page(0))).data).toBe(true);
  const nonce = (fake.session.data.get("save:1") as { nonce: string }).nonce;
  fake.sentToTabs.length = 0;
  expect(await fake.deliver({ type: "save:offer", nonce: "wrong-nonce-1234" }, framed("save-prompt.html", 7))).toStrictEqual({ ok: false, code: "expired", message: "This prompt has expired." });
  expect(fake.sentToTabs.some((s) => s.message.type === "save:close")).toBe(false);
  expect((await fake.deliver({ type: "save:offer", nonce }, framed("save-prompt.html", 7))).data).toMatchObject({ host: "example.com", username: "alex", selected: "new" });
  expect(await fake.deliver({ type: "save:answer", nonce, accept: "save", target: "new" }, framed("save-prompt.html", 8))).toStrictEqual(NOT_ALLOWED);
  expect(fake.sentToTabs.some((s) => s.message.type === "save:close")).toBe(false);
  // The owner answers; the same id is used for the new login on every try.
  const saved: string[] = [];
  v.createItem = async (...args: unknown[]) => {
    saved.push(args[2] as string);
    return args[2] as string;
  };
  expect((await fake.deliver({ type: "save:answer", nonce, accept: "save", target: "new" }, framed("save-prompt.html", 7))).data).toStrictEqual({ done: true });
  expect(saved).toHaveLength(1);
  expect(saved[0]).toMatch(/^[0-9a-f-]{36}$/);
  // The note in the page names the site only.
  expect(fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => s.message.text)).toStrictEqual(["Login saved for example.com."]);
});

test("S16 / S1: a save into a shared login happens only when the prompt answers with it", async () => {
  v.data.entries = [entry("planted", "https://example.com", "v-team")];
  v.data.entries[0]!.item.login!.username = "alex@example.com";
  expect((await fake.deliver({ type: "page:submitted", username: "alex@example.com", password: "my-password" }, page(0))).data).toBe(true);
  const p = fake.session.data.get("save:1") as { target: string; targets: { id: string; vault?: string }[]; nonce: string };
  expect(p.target).toBe("new");
  expect(p.targets).toStrictEqual([{ id: "planted", name: "planted", username: "alex@example.com", vault: "Team" }]);
});

test("the save frame opened as a page of its own (not in a frame) gets nothing", async () => {
  expect(await fake.deliver({ type: "save:offer", nonce: "x".repeat(10) }, framed("save-prompt.html", 0))).toStrictEqual(NOT_ALLOWED);
});

test('C6: "Never for this site" and the settings are read and written inside the storage queue (nothing is lost)', async () => {
  await Promise.all([
    fake.deliver({ type: "settings", patch: { theme: "dark" } }, popup),
    fake.deliver({ type: "settings", patch: { badge: false } }, popup),
    fake.deliver({ type: "settings", patch: { showIcons: false } }, popup),
  ]);
  expect(fake.local.data.get("settings")).toMatchObject({ theme: "dark", badge: false, showIcons: false });
  await fake.local.set({ neverSave: ["a.test", "b.test", "c.test"] });
  await Promise.all([fake.deliver({ type: "neverSave:remove", domain: "a.test" }, popup), fake.deliver({ type: "neverSave:remove", domain: "c.test" }, popup)]);
  expect(fake.local.data.get("neverSave")).toStrictEqual(["b.test"]);
});

test("a save the server's storage limit refuses: the prompt says so in plain words and keeps the save for another try", async () => {
  expect((await fake.deliver({ type: "page:submitted", username: "alex", password: "pw" }, page(0))).data).toBe(true);
  const nonce = (fake.session.data.get("save:1") as { nonce: string }).nonce;
  expect((await fake.deliver({ type: "save:offer", nonce }, framed("save-prompt.html", 7))).ok).toBe(true);
  const create = v.createItem;
  v.createItem = async () => {
    throw Object.assign(new Error("You've reached this server's storage limit. Delete items or ask the server's admin."), { code: "quota_exceeded" });
  };
  try {
    const r = await fake.deliver({ type: "save:answer", nonce, accept: "save", target: "new" }, framed("save-prompt.html", 7));
    expect(r.data).toStrictEqual({ error: "You've reached this server's storage limit. Delete items or ask the server's admin.", retry: true });
    expect(fake.session.data.has("save:1")).toBe(true);
  } finally {
    v.createItem = create;
  }
});

test("the popup's item list says why the last fill on its tab's page didn't work, for that page only", async () => {
  await fake.session.set({ "fillProblem:1": { reason: "PassAuth couldn't find a login form on this page.", url: TAB.url, expires: Date.now() + 60_000 } });
  const here = await fake.deliver({ type: "items", url: TAB.url, tabId: 1 }, popup);
  expect(here.data.fillProblem).toBe("PassAuth couldn't find a login form on this page.");
  const other = await fake.deliver({ type: "items", url: "https://example.com/elsewhere", tabId: 1 }, popup);
  expect(other.data.fillProblem).toBeUndefined();
  // A content script can't ask for it.
  expect(await fake.deliver({ type: "items", url: TAB.url, tabId: 1 }, page(0))).toStrictEqual(NOT_ALLOWED);
});

/** Records `updateItem` calls for one test (the mock's own is a no-op). */
async function capturingUpdates(run: (updates: Item[]) => Promise<void>) {
  const before = v.updateItem;
  const updates: Item[] = [];
  v.updateItem = (async (_e: unknown, item: Item) => {
    updates.push(item);
  }) as typeof v.updateItem;
  try {
    await run(updates);
  } finally {
    v.updateItem = before;
  }
}

test("Add to an existing login (popup): lists logins not saved for the page; adds the page's origin with the default match", async () => {
  v.data.entries = [entry("gmail", "https://gmail.com"), entry("here", "https://example.com")];
  const targets = await fake.deliver({ type: "addSite:targets", url: "https://example.com/login" }, popup);
  expect(targets.data.map((t: { id: string }) => t.id)).toStrictEqual(["gmail"]);
  await capturingUpdates(async (updates) => {
    expect((await fake.deliver({ type: "addSite", id: "gmail", url: "https://example.com/login?x=1" }, popup)).data).toBe(true);
    expect(updates[0]?.login?.urls).toStrictEqual([
      { url: "https://gmail.com", match: "domain" },
      { url: "https://example.com", match: "default" },
    ]);
    // Already saved for the page: nothing changes.
    expect((await fake.deliver({ type: "addSite", id: "here", url: "https://example.com/login" }, popup)).data).toBe(false);
    expect(updates).toHaveLength(1);
  });
  // Only http(s) pages, and never from a page.
  expect(await fake.deliver({ type: "addSite", id: "gmail", url: "chrome://settings" }, popup)).toStrictEqual(NOT_ALLOWED);
  expect(await fake.deliver({ type: "addSite", id: "gmail", url: "https://example.com/" }, page(0))).toStrictEqual(NOT_ALLOWED);
});

test("save prompt: the typed user name and password of a login for another site offer 'add this site'; the page never learns which login", async () => {
  v.data.entries = [entry("gmail", "https://gmail.com"), entry("team", "https://team.test", "v-team")];
  expect((await fake.deliver({ type: "page:submitted", username: "Alex", password: "secret-pw" }, page(0))).data).toBe(true);
  const nonce = (fake.session.data.get("save:1") as { nonce: string }).nonce;
  const offer = (await fake.deliver({ type: "save:offer", nonce }, framed("save-prompt.html", 7))).data;
  // Own vault only (never a shared one), and never preselected.
  expect(offer).toMatchObject({ targets: [], selected: "new", addTo: [{ id: "gmail", name: "gmail", username: "alex" }] });
  fake.sentToTabs.length = 0;
  await capturingUpdates(async (updates) => {
    expect((await fake.deliver({ type: "save:answer", nonce, accept: "save", target: "gmail" }, framed("save-prompt.html", 7))).data).toStrictEqual({ done: true });
    expect(updates[0]?.login?.urls.map((u) => u.url)).toStrictEqual(["https://gmail.com", "https://example.com"]);
    expect(updates[0]?.login?.password).toBe("secret-pw");
  });
  const toasts = fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => s.message.text as string);
  expect(toasts).toStrictEqual(["example.com added to your login."]);
});

test("save prompt: another password, or no user name, offers no 'add this site'", async () => {
  v.data.entries = [entry("gmail", "https://gmail.com")];
  for (const [username, password] of [
    ["alex", "other-pw"],
    ["", "secret-pw"],
  ]) {
    expect((await fake.deliver({ type: "page:submitted", username, password }, page(0))).data).toBe(true);
    const nonce = (fake.session.data.get("save:1") as { nonce: string }).nonce;
    const offer = (await fake.deliver({ type: "save:offer", nonce }, framed("save-prompt.html", 7))).data;
    expect(offer.addTo, `${username}/${password}`).toBeUndefined();
    await fake.deliver({ type: "save:answer", nonce, accept: "dismiss", target: "new" }, framed("save-prompt.html", 7));
  }
});
