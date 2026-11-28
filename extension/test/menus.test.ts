// The right-click menus (background/menus.ts): the pure model for every state (signed out, locked, no login, one,
// several, hidden sites, the setting off), titles without secrets, the rebuild through chrome.contextMenus, and
// clicks that check the clicked frame and the tab's current address before filling or copying.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { actionMenuModel, applyMenu, forBrowser, MAX_LISTED, menuClick, menuModel, menuText } = await import("../src/background/menus");
const { afterUnlock, PENDING_MS } = await import("../src/background/commands");
const { markUsed } = await import("../src/background/last-used");

type MenuLogin = Parameters<typeof menuModel>[1][number];
const ON = { contextMenu: true };
const m = (id: string, name = id, username = "alex", extra: Partial<MenuLogin> = {}): MenuLogin => ({ id, name, username, hasPassword: true, hasTotp: false, ...extra });
const ids = (entries: { id: string }[]) => entries.map((e) => e.id);
const byId = (entries: ReturnType<typeof menuModel>, id: string) => entries.find((e) => e.id === id);
/** The titles a user sees: no separators, nothing hidden ("Fill a strong password" outside password fields). */
const shown = (entries: ReturnType<typeof menuModel>) => entries.filter((x) => !x.separator && x.visible !== false);

// ------------------------------------------------------------------ the model

test("the setting off: no page entries at all", () => {
  expect(menuModel({ status: "unlocked", host: "example.com" }, [m("a")], { contextMenu: false }, false)).toStrictEqual([]);
});

test("signed out: only 'Sign in to PassAuth…'", () => {
  const e = menuModel({ status: "signed-out", host: "example.com" }, [], ON, false);
  expect(ids(e)).toStrictEqual(["pa", "pa:signin"]);
  expect(byId(e, "pa:signin")?.title).toBe("Sign in to PassAuth…");
});

test("locked: 'Unlock to fill…' in fields, a strong password and Open PassAuth everywhere; none of the fill entry on a hidden site", () => {
  const e = menuModel({ status: "locked", host: "example.com" }, [], ON, false);
  expect(e.filter((x) => !x.separator).map((x) => x.title)).toStrictEqual(["PassAuth", "Unlock to fill…", "Copy a strong password", "Open PassAuth"]);
  expect(byId(e, "pa:unlock")?.contexts).toStrictEqual(["editable"]);
  expect(byId(e, "pa:gen")?.contexts).toStrictEqual(["page", "editable", "selection", "link", "frame"]);
  const hidden = menuModel({ status: "locked", host: "example.com" }, [], ON, true);
  expect(ids(hidden)).not.toContain("pa:unlock");
  // No separator before the first entry shown in a page.
  expect(hidden[1]?.separator).toBeUndefined();
});

test("no login for the page: says so, offers to add one", () => {
  const e = menuModel({ status: "unlocked", host: "shop.example.com" }, [], ON, false);
  expect(byId(e, "pa:none")).toMatchObject({ title: "No logins for shop.example.com", enabled: false });
  expect(byId(e, "pa:add")?.title).toBe("Add a login for shop.example.com…");
  expect(ids(e)).toContain("pa:gen");
  expect(ids(e)).toContain("pa:open");
});

test("one login: Fill '<name> · <user name>' in fields, then its copies (the code only when it has one)", () => {
  const e = menuModel({ status: "unlocked", host: "example.com" }, [m("i1", "Example", "alex")], ON, false);
  expect(shown(e).map((x) => x.title)).toStrictEqual(["PassAuth", "Fill Example · alex", "Copy user name", "Copy password", "Copy a strong password", "Open PassAuth"]);
  expect(byId(e, "pa:fill:i1")?.contexts).toStrictEqual(["editable"]);
  expect(byId(e, "pa:pass:i1")?.contexts).toStrictEqual(["page", "editable", "selection", "link", "frame"]);
  const withCode = menuModel({ status: "unlocked", host: "example.com" }, [m("i1", "Example", "alex", { hasTotp: true })], ON, false);
  expect(byId(withCode, "pa:code:i1")?.title).toBe("Copy verification code");
  // A hidden site keeps the copies, never the fill.
  expect(ids(menuModel({ status: "unlocked", host: "example.com" }, [m("i1")], ON, true))).not.toContain("pa:fill:i1");
});

test("several logins: submenus listing them in the given (last used) order, at most 10, then 'More in PassAuth…'", () => {
  const logins = Array.from({ length: 12 }, (_, n) => m(`i${n}`, `Login ${n}`, `user${n}`, { hasTotp: n === 3 }));
  const e = menuModel({ status: "unlocked", host: "example.com" }, logins, ON, false);
  const children = (parent: string) => shown(e).filter((x) => x.parentId === parent);
  expect(children("pa").map((x) => x.title)).toStrictEqual(["Fill", "Copy user name", "Copy password", "Copy verification code", "Copy a strong password", "Open PassAuth"]);
  expect(children("pa:fill").map((x) => x.title)).toStrictEqual([...logins.slice(0, MAX_LISTED).map((l) => `${l.name} · ${l.username}`), "More in PassAuth…"]);
  expect(children("pa:fill").every((x) => x.contexts.join() === "editable")).toBe(true);
  // Only the login with a code is under "Copy verification code"; no "More" for a short list.
  expect(children("pa:code").map((x) => x.id)).toStrictEqual(["pa:code:i3"]);
  // Hidden site: no Fill submenu.
  expect(ids(menuModel({ status: "unlocked", host: "example.com" }, logins, ON, true))).not.toContain("pa:fill");
});

test("titles: an item's name and user name only; '&' and '%s' can't turn into a mnemonic or the selected text", () => {
  expect(menuText("Tom & Jerry %s")).toBe("Tom && Jerry %​s");
  expect(menuText("x".repeat(100)).length).toBe(60);
  const e = menuModel({ status: "unlocked", host: "example.com" }, [m("i1", "A & B", "")], ON, false);
  expect(byId(e, "pa:fill:i1")?.title).toBe("Fill A && B");
  // The model has no field for a password or a code at all.
  expect(Object.keys(m("x")).sort()).toStrictEqual(["hasPassword", "hasTotp", "id", "name", "username"]);
});

test("toolbar icon menu: at most 6 entries; Lock only while unlocked", () => {
  for (const s of ["signed-out", "locked", "unlocked"] as const) {
    const e = actionMenuModel(s);
    expect(e.length).toBeLessThanOrEqual(6);
    expect(e.every((x) => x.contexts.join() === "action")).toBe(true);
  }
  expect(actionMenuModel("unlocked").map((x) => x.title)).toStrictEqual(["Lock now", "Sync now", "Generator", "Open web vault"]);
  expect(actionMenuModel("locked")[0]?.enabled).toBe(false);
});

// ------------------------------------------------------------ with the vault

let fake: FakeChrome;
let server: FakeServer;
const TAB = { id: 1, url: "https://example.com/login", windowId: 1, active: true };

const login = (name: string, url: string, username = "alex", totp: string | null = null) =>
  JSON.stringify({
    name,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username, password: `pw-${name}`, urls: [{ url, match: "domain" }], totp, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });

async function signedIn(items: [string, string, string?][], unlocked = true) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.items = items.map(([id, url, name = id]) => ({ id, vault_id: "v-own", item_key: `own-1:${id}`, data: login(name, url), revision: 1, deleted_at: null }));
  vi.stubGlobal("fetch", server.fetch);
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  fake.tabs.set(TAB.id, { ...TAB });
  fake.setTabResponder((s) => (s.message.type === "fill" ? { filled: true } : undefined));
  if (unlocked) {
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
  }
}

const click = (menuItemId: string, frame: { frameId?: number; frameUrl?: string } = {}, tab = TAB) =>
  menuClick({ menuItemId, editable: true, pageUrl: tab.url, frameId: 0, ...frame } as chrome.contextMenus.OnClickData, { ...tab } as chrome.tabs.Tab);
const copies = () => fake.runtimeMessages.filter((r: any) => r?.type === "offscreen:copy").map((r: any) => r.text);
const toasts = () => fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => s.message.text);
const fills = () => fake.sentToTabs.filter((s) => s.message.type === "fill");

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("Safari: no toolbar icon menu and no 'frame' context; other browsers get the entries as they are", () => {
  const entries = [...menuModel({ status: "unlocked", host: "example.com" }, [m("i1")], ON, false), ...actionMenuModel("unlocked")];
  expect(forBrowser(entries)).toStrictEqual(entries);
  const real = globalThis.chrome.runtime.getURL;
  globalThis.chrome.runtime.getURL = (p: string) => `safari-web-extension://ABC/${p}`;
  try {
    const safari = forBrowser(entries);
    expect(safari.some((e) => e.id.startsWith("pa-action:"))).toBe(false);
    for (const e of safari) expect(e.contexts).not.toContain("frame");
    expect(ids(safari)).toStrictEqual(ids(entries.filter((e) => !e.id.startsWith("pa-action:"))));
    expect(safari.find((e) => e.id === "pa")?.contexts).toStrictEqual(["page", "editable", "selection", "link"]);
  } finally {
    globalThis.chrome.runtime.getURL = real;
  }
});

test("the rebuild: entries for the active tab, last used first, page entries only on http(s) pages", async () => {
  await signedIn([
    ["i1", "https://example.com", "First"],
    ["i2", "https://example.com", "Second"],
    ["i3", "https://other.test", "Other"],
  ]);
  await markUsed("a1", "i2");
  await applyMenu();
  const fillList = [...fake.menus.values()].filter((e) => e.parentId === "pa:fill").map((e) => e.title);
  expect(fillList).toStrictEqual(["Second · alex", "First · alex"]);
  expect(fake.menus.get("pa")?.documentUrlPatterns).toStrictEqual(["http://*/*", "https://*/*"]);
  expect(fake.menus.get("pa-action:lock")?.contexts).toStrictEqual(["action"]);
  // Nothing in any title is a password.
  for (const e of fake.menus.values()) expect(String(e.title ?? "")).not.toMatch(/pw-/);

  // Locked: the same menu becomes "Unlock to fill…".
  await vault.lockAll();
  await applyMenu();
  expect(fake.menus.has("pa:unlock")).toBe(true);
  expect(fake.menus.has("pa:fill")).toBe(false);
});

test("copy from the menu: checked against the frame and the tab, copied, noted as used, and a page-safe note", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  await click("pa:pass:i1", { frameUrl: "https://example.com/login" });
  expect(copies()).toStrictEqual(["pw-Example"]);
  expect(toasts()).toStrictEqual(["Password copied. It clears in 30 seconds."]);
  expect(Object.keys((await chrome.storage.local.get("lastUsed:a1"))["lastUsed:a1"] ?? {})).toStrictEqual(["i1"]);

  // A frame on another site (the menu was built for the tab's page): nothing copied.
  await click("pa:pass:i1", { frameId: 4, frameUrl: "https://evil.test/frame" });
  // The tab moved on to another site since the menu was built: nothing copied either.
  fake.tabs.set(TAB.id, { ...TAB, url: "https://other.test/" });
  await click("pa:user:i1", { frameUrl: "https://example.com/login" });
  expect(copies()).toStrictEqual(["pw-Example"]);
  expect(toasts().slice(1)).toStrictEqual(["This login isn't saved for this site. Open PassAuth to check its websites.", "This login isn't saved for this site. Open PassAuth to check its websites."]);
});

test("the clipboard delay in the note follows the setting", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  await fake.local.set({ settings: { clearClipboard: 120 } });
  await click("pa:user:i1", { frameUrl: "https://example.com/login" });
  await fake.local.set({ settings: { clearClipboard: 0 } });
  await click("pa:user:i1", { frameUrl: "https://example.com/login" });
  expect(toasts()).toStrictEqual(["User name copied. It clears in 2 minutes.", "User name copied."]);
});

test("fill from the menu: into the right-clicked frame; refused on a hidden site and for a frame of another site", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  await click("pa:fill:i1", { frameId: 0, frameUrl: "https://example.com/login" });
  expect(fills()).toHaveLength(1);
  expect(fills()[0]).toMatchObject({ options: { frameId: 0 }, message: { username: "alex", password: "pw-Example", focused: true } });

  await click("pa:fill:i1", { frameId: 5, frameUrl: "https://evil.test/login" });
  await fake.local.set({ hiddenSites: ["example.com"] });
  await click("pa:fill:i1", { frameId: 0, frameUrl: "https://example.com/login" });
  expect(fills()).toHaveLength(1);
  expect(toasts().at(-1)).toBe("PassAuth's fill entries are hidden on this site. Show them again in PassAuth's settings.");
});

test("'Add a login for <host>…' asks the popup for a new login with the page's address", async () => {
  await signedIn([]);
  await click("pa:add");
  expect((await chrome.storage.session.get("popupRoute")).popupRoute).toStrictEqual({ page: "new", kind: "login", url: "https://example.com" });
  expect(fake.action.popupOpened).toBe(1);
});

test("'Copy a strong password' uses the generator's saved options", async () => {
  await signedIn([]);
  await fake.local.set({ generatorOptions: { mode: "passphrase", passphrase: { words: 6 } } });
  await click("pa:gen");
  expect(copies()).toStrictEqual(["generated passphrase"]);
  expect(toasts()).toStrictEqual(["Passphrase copied. It clears in 30 seconds."]);
});

test("'Unlock to fill…': remembered for 2 minutes, done after the unlock when exactly one login fits", async () => {
  await signedIn([["i1", "https://example.com", "Example"]], false);
  await click("pa:unlock", { frameId: 0, frameUrl: "https://example.com/login" });
  expect(fake.action.popupOpened).toBe(1);
  expect(fills()).toHaveLength(0);
  await vault.unlock("pw");
  expect(await afterUnlock()).toStrictEqual({ filled: true });
  expect(fills()).toHaveLength(1);
  // Used up.
  expect(await afterUnlock()).toStrictEqual({ filled: false });
});

test("'Unlock to fill…' doesn't fill after the time is up, on another page, or with several logins", async () => {
  await signedIn(
    [
      ["i1", "https://example.com", "One"],
      ["i2", "https://example.com", "Two"],
    ],
    false,
  );
  await click("pa:unlock", { frameUrl: "https://example.com/login" });
  await vault.unlock("pw");
  expect(await afterUnlock()).toStrictEqual({ filled: false });

  await vault.lockAll();
  server.items = server.items.slice(0, 1);
  await click("pa:unlock", { frameUrl: "https://example.com/login" });
  fake.tabs.set(TAB.id, { ...TAB, url: "https://example.com/elsewhere" });
  await vault.unlock("pw");
  await vault.sync();
  expect(await afterUnlock()).toStrictEqual({ filled: false });

  await vault.lockAll();
  fake.tabs.set(TAB.id, { ...TAB });
  await click("pa:unlock", { frameUrl: "https://example.com/login" });
  const later = Date.now() + PENDING_MS + 1000;
  vi.spyOn(Date, "now").mockReturnValue(later);
  await vault.unlock("pw");
  expect(await afterUnlock()).toStrictEqual({ filled: false });
  expect(fills()).toHaveLength(0);
});

test("the toolbar icon's menu: Lock now locks; Generator opens the generator", async () => {
  await signedIn([]);
  await menuClick({ menuItemId: "pa-action:generator", editable: false } as chrome.contextMenus.OnClickData);
  expect((await chrome.storage.session.get("popupRoute")).popupRoute).toStrictEqual({ page: "generator" });
  await menuClick({ menuItemId: "pa-action:lock", editable: false } as chrome.contextMenus.OnClickData);
  expect(await vault.lockStatus()).toBe("locked");
});

// ------------------------------------------------- cards, identities, strong passwords

const { noteContextField, STRONG_ID } = await import("../src/background/menus");
const { fillProblem, forgetFillProblem } = await import("../src/background/fill-problems");

const itemJson = (name: string, extra: Record<string, unknown>) =>
  JSON.stringify({
    name,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: null,
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
    ...extra,
  });
const card = (name: string, last4: string) =>
  itemJson(name, { card: { cardholder_name: "Alex Morgan", number: `424242424242${last4}`, brand: "Visa", exp_month: "9", exp_year: "2028", code: "123" } });
const identity = (name: string) =>
  itemJson(name, {
    identity: {
      title: "",
      first_name: "Alex",
      middle_name: "",
      last_name: "Morgan",
      company: "",
      email: "alex@example.com",
      phone: "",
      address1: "1 Main St",
      address2: "",
      city: "Springfield",
      state: "",
      postal_code: "",
      country: "",
      username: "",
      ssn: "123-45-6789",
      passport_number: "X1",
      license_number: "L1",
    },
  });

async function withWallet(unlocked = true) {
  await signedIn([["i1", "https://example.com", "Example"]], false);
  server.items.push(
    { id: "c1", vault_id: "v-own", item_key: "own-1:c1", data: card("Old card", "1111"), revision: 1, deleted_at: null },
    { id: "c2", vault_id: "v-own", item_key: "own-1:c2", data: card("My Visa", "4242"), revision: 1, deleted_at: null },
    { id: "p1", vault_id: "v-own", item_key: "own-1:p1", data: identity("Home"), revision: 1, deleted_at: null },
  );
  fake.setTabResponder((s) => (["fill", "fill:card", "fill:identity"].includes(s.message.type) ? { filled: true } : undefined));
  if (unlocked) {
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
  }
}

test("the model: 'Fill card ›' (https only) and 'Fill identity ›' after the logins, at most 10 each; nothing of them on a hidden site or while locked", () => {
  const cards = Array.from({ length: 12 }, (_, n) => ({ id: `c${n}`, title: `Card ${n} · Visa •••• 42${n}` }));
  const extras = { cards, identities: [{ id: "p1", title: "Alex Morgan · Home" }], https: true, passwordField: false };
  const e = menuModel({ status: "unlocked", host: "shop.example.com" }, [m("i1")], ON, false, extras);
  const kids = (parent: string) => shown(e).filter((x) => x.parentId === parent);
  expect(kids("pa").map((x) => x.title)).toContain("Fill card");
  expect(kids("pa:card").map((x) => x.title)).toStrictEqual([...cards.slice(0, MAX_LISTED).map((c) => c.title), "More in PassAuth…"]);
  expect(kids("pa:identity").map((x) => x.title)).toStrictEqual(["Alex Morgan · Home"]);
  expect(e.filter((x) => x.parentId === "pa:card" || x.parentId === "pa:identity").every((x) => x.contexts.join() === "editable")).toBe(true);
  // Not on http pages (cards), not on hidden sites, not while locked.
  expect(ids(menuModel({ status: "unlocked", host: "shop.example.com" }, [], ON, false, { ...extras, https: false }))).not.toContain("pa:card");
  expect(ids(menuModel({ status: "unlocked", host: "shop.example.com" }, [], ON, true, extras))).not.toContain("pa:identity");
  expect(ids(menuModel({ status: "locked", host: "shop.example.com" }, [], ON, false, extras))).not.toContain("pa:card");
});

test("the model: 'Fill a strong password' is there while unlocked, shown only in a password field", () => {
  const hidden = menuModel({ status: "unlocked", host: "example.com" }, [], ON, false, { cards: [], identities: [], https: true, passwordField: false });
  expect(byId(hidden, STRONG_ID)).toMatchObject({ title: "Fill a strong password", contexts: ["editable"], visible: false });
  const visible = menuModel({ status: "unlocked", host: "example.com" }, [], ON, false, { cards: [], identities: [], https: true, passwordField: true });
  expect(byId(visible, STRONG_ID)?.visible).toBeUndefined();
  expect(ids(menuModel({ status: "locked", host: "example.com" }, [], ON, false))).not.toContain(STRONG_ID);
  expect(ids(menuModel({ status: "unlocked", host: "example.com" }, [], ON, true))).not.toContain(STRONG_ID);
});

test("the rebuild lists the account's cards (name and last four digits) and identities, the one used last first", async () => {
  await withWallet();
  await markUsed("a1", "c2");
  await applyMenu();
  const under = (parent: string) => [...fake.menus.values()].filter((e) => e.parentId === parent).map((e) => e.title);
  expect(under("pa:card")).toStrictEqual(["My Visa · Visa •••• 4242", "Old card · Visa •••• 1111"]);
  expect(under("pa:identity")).toStrictEqual(["Alex Morgan · Home"]);
  // No card number, security code or ID number in any title.
  for (const e of fake.menus.values()) expect(String(e.title ?? "")).not.toMatch(/4242424242|123-45|X1/);
});

test("a card or identity from the menu: filled into the right-clicked frame after the checks; refused for another site's frame and on hidden sites", async () => {
  await withWallet();
  await click("pa:card:c2", { frameId: 0, frameUrl: "https://example.com/checkout" });
  await click("pa:identity:p1", { frameId: 0, frameUrl: "https://example.com/checkout" });
  const sent = fake.sentToTabs.filter((s) => s.message.type === "fill:card" || s.message.type === "fill:identity");
  expect(sent.map((s) => [s.message.type, s.options?.frameId, s.message.focused])).toStrictEqual([
    ["fill:card", 0, true],
    ["fill:identity", 0, true],
  ]);
  expect(sent[0]?.message.card.number).toBe("4242424242424242");
  // Never ID, passport or licence numbers.
  expect(JSON.stringify(sent[1]?.message)).not.toMatch(/123-45|X1|L1/);

  await click("pa:card:c2", { frameId: 4, frameUrl: "https://evil.test/frame" });
  await fake.local.set({ hiddenSites: ["example.com"] });
  await click("pa:identity:p1", { frameId: 0, frameUrl: "https://example.com/checkout" });
  expect(fake.sentToTabs.filter((s) => s.message.type === "fill:card" || s.message.type === "fill:identity")).toHaveLength(2);
  expect(toasts().slice(-2)).toStrictEqual([
    "PassAuth fills cards only on secure (https) pages of the site you're on.",
    "PassAuth's fill entries are hidden on this site. Show them again in PassAuth's settings.",
  ]);
});

test("a card clicked in a menu built before PassAuth locked: filled right after the unlock (that card, re-checked)", async () => {
  await withWallet(false);
  await click("pa:card:c2", { frameId: 0, frameUrl: "https://example.com/checkout" });
  expect(fake.action.popupOpened).toBe(1);
  await vault.unlock("pw");
  expect(await afterUnlock()).toStrictEqual({ filled: true });
  expect(fake.sentToTabs.filter((s) => s.message.type === "fill:card").map((s) => s.message.card.number)).toStrictEqual(["4242424242424242"]);
});

test("'Fill a strong password': shown when the user moves into a password field on the tab's site (not another site's frame)", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  await applyMenu();
  expect(fake.menus.get(STRONG_ID)?.visible).toBe(false);
  const sender = (origin: string, frameId = 0) => ({ id: "x", origin, url: `${origin}/signup`, frameId, tab: { id: TAB.id, url: TAB.url, active: true } }) as chrome.runtime.MessageSender;
  noteContextField(sender("https://evil.test", 3), true);
  expect(fake.menus.get(STRONG_ID)?.visible).toBe(false);
  noteContextField(sender("https://example.com"), true);
  expect(fake.menus.get(STRONG_ID)?.visible).toBe(true);
  // The next rebuild draws it the same way.
  await applyMenu();
  expect(fake.menus.get(STRONG_ID)?.visible).toBeUndefined();
  noteContextField(sender("https://example.com"), false);
  expect(fake.menus.get(STRONG_ID)?.visible).toBe(false);
});

test("'Fill a strong password': the right-clicked password field and its confirmation, then a pending save marked generated", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  fake.setTabResponder((s) => {
    if (s.message.type === "context:field") return { password: true, minLength: 12, maxLength: 64 };
    if (s.message.type === "fill:generated") return { filled: true, username: "alex" };
    return undefined;
  });
  await click("pa:strong", { frameId: 0, frameUrl: "https://example.com/signup" });
  const sent = fake.sentToTabs.map((s) => s.message.type);
  expect(sent).toStrictEqual(["context:field", "fill:generated"]);
  // The frame gets the origin checked for it (no site rules on the page side).
  expect(fake.sentToTabs[1]?.message).toMatchObject({ field: "context", origin: "https://example.com", password: "generated-password" });
  const pending = fake.session.data.get(`save:${TAB.id}`) as { generated?: boolean; password: string; username: string };
  expect([pending.generated, pending.password, pending.username]).toStrictEqual([true, "generated-password", "alex"]);
});

test("'Fill a strong password' on a field that isn't a password field: nothing filled, a note, and the reason kept for the popup", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  fake.setTabResponder((s) => (s.message.type === "context:field" ? { password: false } : undefined));
  await click("pa:strong", { frameId: 0, frameUrl: "https://example.com/signup" });
  expect(fake.sentToTabs.some((s) => s.message.type === "fill:generated")).toBe(false);
  expect(toasts()).toStrictEqual(["Right-click a password field to fill a strong password there."]);
  expect(await fillProblem(TAB.id, TAB.url)).toBe("Right-click a password field to fill a strong password there.");
});

test("why a fill didn't work is kept per tab for the popup (no secrets), for that page only, and goes with a fill that works or a navigation", async () => {
  await signedIn([["i1", "https://example.com", "Example"]]);
  fake.setTabResponder((s) => (s.message.type === "fill" ? { filled: false } : undefined));
  await click("pa:fill:i1", { frameId: 0, frameUrl: "https://example.com/login" });
  expect(toasts()).toStrictEqual(["PassAuth couldn't find a login form on this page."]);
  const reason = await fillProblem(TAB.id, TAB.url);
  expect(reason).toBe("PassAuth couldn't find a login form on this page.");
  expect(JSON.stringify([...fake.session.data.entries()].filter(([k]) => k.startsWith("fillProblem:")))).not.toContain("pw-Example");
  // Another page of the tab: not this problem.
  expect(await fillProblem(TAB.id, "https://example.com/other")).toBeUndefined();
  // A fill that works clears it.
  fake.setTabResponder((s) => (s.message.type === "fill" ? { filled: true } : undefined));
  await click("pa:fill:i1", { frameId: 0, frameUrl: "https://example.com/login" });
  expect(await fillProblem(TAB.id, TAB.url)).toBeUndefined();
  // So does a navigation (main.ts calls this on tabs.onUpdated).
  fake.setTabResponder((s) => (s.message.type === "fill" ? { filled: false } : undefined));
  await click("pa:fill:i1", { frameId: 0, frameUrl: "https://example.com/login" });
  await forgetFillProblem(TAB.id);
  expect(await fillProblem(TAB.id, TAB.url)).toBeUndefined();
});
