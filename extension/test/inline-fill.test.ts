// The inline menu v2 and filling, background side (vault mocked): fillItem() by item type with the frame rules of
// login fills (claims checked by real origin, secrets to one document, cards only on https), "Hide on this site",
// "Use a strong password" and its pending save, "New login", the rows per field kind, the note after a failed fill
// from the menu, and the save prompt shown by the background after a page load (content scripts don't ask).

import type { Item } from "@web/lib/types";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { EXTENSION_ID, installedChrome, resetChrome, type SentToTab } from "./chrome";

const v = vi.hoisted(() => {
  type E = { id: string; item: Item; vaultId: string; revision: number; enc: object };
  const data = { unlocked: true, entries: [] as E[], generated: [] as unknown[] };
  const nothing = async () => {};
  return {
    data,
    setLockCheck: () => {},
    setKeysDroppedHandler: () => {},
    ensureUnlocked: async () => data.unlocked,
    unlockedIndex: async () => null,
    allEntries: () => data.entries,
    getEntry: (id: string) => data.entries.find((e) => e.id === id),
    isPersonal: () => true,
    canWrite: () => true,
    vaultName: () => "Personal",
    weakPassword: () => false,
    summarize: (e: E) => ({
      id: e.id,
      name: e.item.name,
      subtitle: e.item.login?.username ?? "",
      host: "",
      url: "",
      folder: "",
      kind: e.item.card ? "card" : e.item.identity ? "identity" : "login",
      favorite: false,
      hasPassword: true,
      hasTotp: !!e.item.login?.totp,
      passkeys: 0,
      vaultName: "",
    }),
    totp: () => ({ code: "123456", remaining: 20, period: 30, expires: Date.now() + 20_000 }),
    generate: async (mode: string, options?: Record<string, unknown>) => {
      data.generated.push({ mode, options });
      return mode === "password" ? `P${"x".repeat(Number(options?.length ?? 20) - 1)}` : "correct-horse-battery-staple";
    },
    owner: () => ({ id: "a1", generation: 1 }),
    stillOwner: () => true,
    refreshIfStale: nothing,
    createItem: async () => "new-id",
    updateItem: nothing,
    lockStatus: async () => (data.unlocked ? "unlocked" : "locked"),
  };
});
vi.mock("../src/background/vault", () => v);

const { onMessage } = await import("../src/background/router");
const { fillItem } = await import("../src/background/fill");
const { onTabUpdated } = await import("../src/background/save-prompt");
const fake = installedChrome();
fake.chrome.runtime.onMessage.addListener(onMessage);

const TAB = { id: 1, url: "https://shop.example/checkout", windowId: 1, active: true };
const page = (frameId = 0, origin = "https://shop.example", url = `${origin}/checkout`) => ({
  id: EXTENSION_ID,
  url,
  origin,
  frameId,
  documentId: `doc-${frameId}-${origin}`,
  tab: { id: TAB.id, url: TAB.url },
});
const menuFrame = {
  id: EXTENSION_ID,
  url: `chrome-extension://${EXTENSION_ID}/inline-menu.html`,
  origin: `chrome-extension://${EXTENSION_ID}`,
  frameId: 9,
  documentId: "doc-menu",
  tab: { id: TAB.id, url: TAB.url },
};

const base = (name: string): Item => ({
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
});
const entry = (id: string, item: Item) => ({ id, item, vaultId: "v-own", revision: 1, enc: {} });
const card = (id = "c1") => entry(id, { ...base("Personal card"), card: { cardholder_name: "Alex Morgan", brand: "", number: "4242424242424242", exp_month: "9", exp_year: "2028", code: "123" } });
const identity = (id = "i1") =>
  entry(id, {
    ...base("Home"),
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
      postal_code: "94000",
      country: "US",
      username: "",
      ssn: "123-45-6789",
      passport_number: "P123",
      license_number: "L123",
    },
  });
const login = (id: string, totp: string | null = null) =>
  entry(id, { ...base(id), login: { username: `${id}@example.com`, password: "secret-pw", urls: [{ url: "https://shop.example", match: "domain" }], totp, passkeys: [] } });

const sent = (type: string) => fake.sentToTabs.filter((s) => s.message.type === type);
const toasts = () => sent("toast").map((s) => s.message.text as string);

/** Content scripts that answer: every frame "fills" what it gets; `claimers` claim offers. */
function frames(claimers: Record<string, unknown>[] = [], filled = true) {
  fake.setTabResponder((s: SentToTab) => {
    if (s.message.type === "fill:offer") {
      for (const sender of claimers) void fake.deliver({ type: "page:fillClaim", token: s.message.token }, sender);
      return null;
    }
    if (s.message.type === "fill:generated") return { filled, username: "alex" };
    if (s.message.type?.startsWith("fill")) return s.options?.frameId === 0 && claimers.length ? { filled: false } : { filled };
    return null;
  });
}

beforeEach(async () => {
  resetChrome(fake);
  fake.tabs.set(TAB.id, TAB);
  v.data.unlocked = true;
  v.data.entries = [];
  v.data.generated = [];
  await fake.local.set({
    accounts: { a1: { server: "https://vault.test", email: "alex@example.com", name: "", tokens: { access: "a", refresh: "r" }, lastSync: 0, persistedKeys: null } },
    active: "a1",
  });
});

describe("fillItem: logins, cards and identities with the frame rules of login fills", () => {
  test("a card goes to the top frame of an https page; the item counts as used", async () => {
    v.data.entries = [card()];
    frames();
    await fillItem("c1", TAB.id);
    const [cmd] = sent("fill:card");
    expect(cmd?.options).toStrictEqual({ frameId: 0 });
    expect(cmd?.message).toStrictEqual({
      type: "fill:card",
      card: { name: "Alex Morgan", number: "4242424242424242", expMonth: "9", expYear: "2028", code: "123", brand: "Visa" },
      origin: "https://shop.example",
      focused: false,
    });
    expect(Object.keys(fake.local.data.get("lastUsed:a1") as object)).toStrictEqual(["c1"]);
  });

  test("never a card on an http page", async () => {
    v.data.entries = [card()];
    fake.tabs.set(TAB.id, { ...TAB, url: "http://shop.example/checkout" });
    frames();
    await expect(fillItem("c1", TAB.id)).rejects.toMatchObject({ code: "cant_fill" });
    expect(sent("fill:card")).toHaveLength(0);
  });

  test("an identity carries no ID, passport or licence numbers", async () => {
    v.data.entries = [identity()];
    frames();
    await fillItem("i1", TAB.id);
    const [cmd] = sent("fill:identity");
    expect(Object.keys(cmd?.message.identity).sort()).toStrictEqual(
      ["address1", "address2", "city", "company", "country", "email", "first_name", "last_name", "middle_name", "phone", "postal_code", "state", "title", "username"].sort(),
    );
    expect(JSON.stringify(cmd?.message)).not.toMatch(/123-45-6789|P123|L123/);
  });

  test("a card form in an iframe: the offer names the kind; only a same-site https frame gets the card, at its document", async () => {
    v.data.entries = [card()];
    frames([page(3, "https://pay.evil.test"), { ...page(4, "https://pay.shop.example"), origin: "null" }, page(5, "http://pay.shop.example"), page(6, "https://pay.shop.example")]);
    await fillItem("c1", TAB.id);
    expect(sent("fill:offer").map((s) => Object.keys(s.message).sort())).toStrictEqual([["kind", "token", "type"]]);
    expect(sent("fill:offer")[0]?.message.kind).toBe("card");
    expect(sent("fill:card").map((s) => s.options)).toStrictEqual([{ frameId: 0 }, { documentId: "doc-6-https://pay.shop.example" }]);
  });

  test("a named frame (right-click menu) is reached only through its own claim; another frame's claim is ignored", async () => {
    v.data.entries = [login("e1")];
    frames([page(4, "https://login.shop.example"), page(7, "https://login.shop.example")]);
    // The offer goes to frame 7 only; frame 4 answering anyway changes nothing.
    await fillItem("e1", TAB.id, 7);
    expect(sent("fill:offer").map((s) => s.options)).toStrictEqual([{ frameId: 7 }]);
    expect(sent("fill").map((s) => s.options)).toStrictEqual([{ documentId: "doc-7-https://login.shop.example" }]);
  });

  test("an about:blank frame stands for the origin it inherited; a sandboxed one (origin null) for nothing", async () => {
    v.data.entries = [card()];
    frames([{ ...page(5, "https://shop.example", "about:blank"), origin: "null" }, page(6, "https://shop.example", "about:blank")]);
    await fillItem("c1", TAB.id);
    expect(sent("fill:card").map((s) => s.options)).toStrictEqual([{ frameId: 0 }, { documentId: "doc-6-https://shop.example" }]);
    const info = await fake.deliver({ type: "page:inlineInfo" }, page(6, "https://shop.example", "about:srcdoc"));
    expect(info.data.mode).toBe("focus");
    expect((await fake.deliver({ type: "page:inlineInfo" }, { ...page(6, "https://shop.example", "about:srcdoc"), origin: "null" })).data.mode).toBe("off");
  });
});

/** Open a menu from the top frame's field and return its nonce. */
async function openMenu(req: Record<string, unknown> = {}) {
  const r = await fake.deliver({ type: "page:inlineOpen", ...req }, page(0));
  expect(r.ok).toBe(true);
  return r.data as string;
}

describe("the inline menu's rows and actions", () => {
  test("rows follow the field: logins last used first, codes on one-time-code fields, cards and identities with their labels", async () => {
    v.data.entries = [login("a"), login("b", "JBSWY3DPEHPK3PXP"), card(), identity()];
    await fake.local.set({ "lastUsed:a1": { b: 2000, a: 1000 } });
    let nonce = await openMenu({ kind: "login" });
    let items = (await fake.deliver({ type: "inline:items", nonce }, menuFrame)).data;
    expect(items.items.map((i: { id: string }) => i.id)).toStrictEqual(["b", "a"]);
    // "⋯ → Hide on shop.example": it names the site it hides (the whole base domain).
    expect(items).toMatchObject({ kind: "login", site: "shop.example", hides: "shop.example", strongPassword: false });

    nonce = await openMenu({ kind: "otp" });
    items = (await fake.deliver({ type: "inline:items", nonce }, { ...menuFrame, documentId: "doc-menu-2" })).data;
    expect(items.items.map((i: { id: string }) => i.id)).toStrictEqual(["b"]);
    expect(items.codes).toMatchObject([{ id: "b", code: "123456", period: 30 }]);

    nonce = await openMenu({ kind: "card" });
    items = (await fake.deliver({ type: "inline:items", nonce }, { ...menuFrame, documentId: "doc-menu-3" })).data;
    expect(items.items.map((i: { name: string; subtitle: string }) => [i.name, i.subtitle])).toStrictEqual([["Personal card", "Visa •••• 4242 · 09/28"]]);

    nonce = await openMenu({ kind: "identity" });
    items = (await fake.deliver({ type: "inline:items", nonce }, { ...menuFrame, documentId: "doc-menu-4" })).data;
    expect(items.items.map((i: { name: string; subtitle: string }) => [i.name, i.subtitle])).toStrictEqual([["Alex Morgan · Home", "alex@example.com"]]);
  });

  test("a fill from a one-time-code field sends only the code, to the field's document", async () => {
    v.data.entries = [login("b", "JBSWY3DPEHPK3PXP")];
    frames();
    const nonce = await openMenu({ kind: "otp" });
    await fake.deliver({ type: "inline:items", nonce }, menuFrame);
    expect((await fake.deliver({ type: "inline:fill", nonce, id: "b" }, menuFrame)).ok).toBe(true);
    const [cmd] = sent("fill");
    expect(cmd?.options).toStrictEqual({ documentId: "doc-0-https://shop.example" });
    expect(cmd?.message).toMatchObject({ username: "", password: "", totp: "123456", focused: true });
  });

  test("a failed fill from the menu says so in the page, always in the same words", async () => {
    v.data.entries = [login("a")];
    frames([], false);
    const nonce = await openMenu();
    await fake.deliver({ type: "inline:items", nonce }, menuFrame);
    const r = await fake.deliver({ type: "inline:fill", nonce, id: "a" }, menuFrame);
    expect(r).toMatchObject({ ok: false, code: "cant_fill" });
    expect(toasts()).toStrictEqual(["PassAuth couldn't fill this page. Open PassAuth for details."]);
  });

  test("I-2: a fill takes only a row the menu was given; any other id is refused and the menu is used up", async () => {
    v.data.entries = [login("a"), card("c1")];
    frames();
    // A login menu never listed the card: its id is refused (no fill, no secrets sent anywhere).
    let nonce = await openMenu({ kind: "login" });
    expect((await fake.deliver({ type: "inline:items", nonce }, menuFrame)).data.items.map((i: { id: string }) => i.id)).toStrictEqual(["a"]);
    expect(await fake.deliver({ type: "inline:fill", nonce, id: "c1" }, menuFrame)).toMatchObject({ ok: false, code: "not_allowed" });
    expect(sent("fill:card")).toStrictEqual([]);
    expect(sent("fill:offer")).toStrictEqual([]);
    expect(await fake.deliver({ type: "inline:fill", nonce, id: "a" }, menuFrame)).toMatchObject({ ok: false, code: "expired" });
    // Before the menu asked for its rows nothing is offered at all.
    nonce = await openMenu({ kind: "login" });
    expect(await fake.deliver({ type: "inline:fill", nonce, id: "a" }, { ...menuFrame, documentId: "doc-menu-2" })).toMatchObject({ ok: false, code: "not_allowed" });
    expect(sent("fill")).toStrictEqual([]);
  });

  test("M-1: Tab, Esc and a touch in the menu reach the field's document through the worker, with the menu's nonce", async () => {
    v.data.entries = [login("a")];
    frames();
    const nonce = await openMenu({ kind: "login" });
    await fake.deliver({ type: "inline:items", nonce }, menuFrame);
    expect((await fake.deliver({ type: "inline:touch", nonce }, menuFrame)).ok).toBe(true);
    expect((await fake.deliver({ type: "inline:return", nonce }, menuFrame)).ok).toBe(true);
    // Another frame with a copy of the nonce gets nothing sent anywhere.
    expect(await fake.deliver({ type: "inline:return", nonce }, { ...menuFrame, frameId: 10, documentId: "doc-other" })).toMatchObject({ ok: false, code: "not_allowed" });
    expect((await fake.deliver({ type: "inline:close", nonce, refocus: true }, menuFrame)).ok).toBe(true);
    const toField = { documentId: "doc-0-https://shop.example" };
    expect(sent("inline:touch").map((s) => [s.message, s.options])).toStrictEqual([[{ type: "inline:touch", nonce }, toField]]);
    expect(sent("inline:return").map((s) => [s.message, s.options])).toStrictEqual([[{ type: "inline:return", nonce }, toField]]);
    expect(sent("inline:close").map((s) => [s.message, s.options])).toStrictEqual([[{ type: "inline:close", refocus: true, nonce }, toField]]);
    // Used up by Esc.
    expect(await fake.deliver({ type: "inline:return", nonce }, menuFrame)).toMatchObject({ ok: false, code: "expired" });
  });

  test("Hide on this site: stored by base domain, every frame drops its icon, no icon or menu there any more", async () => {
    frames();
    // On a subdomain the menu says what goes: the whole site.
    const label = await openMenu();
    const onSub = { ...menuFrame, documentId: "doc-menu-hides", tab: { id: TAB.id, url: "https://www.shop.example/login" } };
    expect((await fake.deliver({ type: "inline:items", nonce: label }, onSub)).data).toMatchObject({ site: "shop.example", hides: "shop.example" });
    const nonce = await openMenu();
    expect((await fake.deliver({ type: "inline:hide", nonce }, menuFrame)).ok).toBe(true);
    expect(fake.local.data.get("hiddenSites")).toStrictEqual(["shop.example"]);
    expect(sent("inline:off").map((s) => s.options)).toStrictEqual([undefined]);
    expect((await fake.deliver({ type: "page:inlineInfo" }, page(0))).data).toStrictEqual({ mode: "off", status: "locked", count: 0 });
    expect((await fake.deliver({ type: "page:inlineOpen" }, page(3, "https://login.shop.example"))).data).toBe(null);
    // Used up.
    expect(await fake.deliver({ type: "inline:hide", nonce }, menuFrame)).toMatchObject({ ok: false, code: "expired" });
  });

  test("New login opens PassAuth at a new login with the page's origin and the typed user name", async () => {
    const nonce = await openMenu({ kind: "login", username: "alex" });
    expect((await fake.deliver({ type: "inline:new", nonce }, menuFrame)).ok).toBe(true);
    expect(fake.session.data.get("popupRoute")).toStrictEqual({ page: "new", kind: "login", url: "https://shop.example", username: "alex" });
    const n2 = await openMenu({ kind: "card" });
    await fake.deliver({ type: "inline:new", nonce: n2 }, { ...menuFrame, documentId: "doc-menu-2" });
    expect(fake.session.data.get("popupRoute")).toStrictEqual({ page: "new", kind: "card" });
  });
});

describe("Use a strong password", () => {
  test("only on a new-password field, only with inlineOnSignup on", async () => {
    frames();
    let nonce = await openMenu({ kind: "login" });
    expect(await fake.deliver({ type: "inline:generate", nonce }, menuFrame)).toMatchObject({ ok: false, code: "not_allowed" });
    await fake.local.set({ settings: { inlineOnSignup: false } });
    nonce = await openMenu({ kind: "new-password" });
    expect((await fake.deliver({ type: "inline:items", nonce }, { ...menuFrame, documentId: "doc-menu-2" })).data.strongPassword).toBe(false);
    expect(await fake.deliver({ type: "inline:generate", nonce }, { ...menuFrame, documentId: "doc-menu-2" })).toMatchObject({ ok: false, code: "not_allowed" });
    expect(sent("fill:generated")).toHaveLength(0);
  });

  test("fills a password from the generator options within the field's limits, and keeps a pending save the prompt follows", async () => {
    frames();
    await fake.local.set({ generatorOptions: { mode: "password", password: { length: 40, symbols: false } } });
    const nonce = await openMenu({ kind: "new-password", maxLength: 24 });
    expect((await fake.deliver({ type: "inline:generate", nonce }, menuFrame)).ok).toBe(true);
    expect(v.data.generated).toMatchObject([{ mode: "password", options: { length: 24, symbols: false } }]);
    const [cmd] = sent("fill:generated");
    expect(cmd?.options).toStrictEqual({ documentId: "doc-0-https://shop.example" });
    const password = cmd?.message.password as string;
    expect(password).toHaveLength(24);
    const p = fake.session.data.get("save:1") as { username: string; password: string; generated: boolean; expires: number };
    expect(p).toMatchObject({ username: "alex", password, generated: true });
    expect(p.expires - Date.now()).toBeGreaterThan(9 * 60_000);

    // The sign-up lands on another page of the site (even one with a password field): the prompt is shown there.
    fake.sentToTabs.length = 0;
    await onTabUpdated(TAB.id, { status: "complete" }, { url: "https://shop.example/welcome" });
    expect(sent("showSave").map((s) => [s.options, s.message.afterLoad])).toStrictEqual([[{ frameId: 0 }, false]]);
    // The prompt doesn't go away by itself for a generated password.
    const offer = await fake.deliver({ type: "save:offer", nonce: sent("showSave")[0]?.message.nonce }, { ...menuFrame, url: `chrome-extension://${EXTENSION_ID}/save-prompt.html` });
    expect(offer.data).toMatchObject({ generated: true, username: "alex" });

    // Submitting the form with that password keeps it a generated password's save.
    await fake.deliver({ type: "page:submitted", username: "alex", password }, page(0));
    expect(fake.session.data.get("save:1")).toMatchObject({ generated: true, password });
  });
});

describe("the save prompt after a page load (no content script asks)", () => {
  test("shown in the top frame of a page on the same site, with the focus only after a keyboard submit", async () => {
    frames();
    expect((await fake.deliver({ type: "page:submitted", username: "alex", password: "pw-1", keyboard: true }, page(0))).data).toBe(true);
    await onTabUpdated(TAB.id, { status: "loading" }, { url: "https://shop.example/home" });
    expect(sent("showSave")).toHaveLength(0);
    await onTabUpdated(TAB.id, { status: "complete" }, { url: "https://shop.example/home" });
    expect(sent("showSave").map((s) => s.message)).toMatchObject([{ focus: true, afterLoad: true }]);
    // Another site in that tab: nothing.
    fake.sentToTabs.length = 0;
    await onTabUpdated(TAB.id, { status: "complete" }, { url: "https://elsewhere.example/" });
    expect(sent("showSave")).toHaveLength(0);
  });

  test("a click submit: no focus; the form going away in a single-page app shows it too", async () => {
    frames();
    await fake.deliver({ type: "page:submitted", username: "alex", password: "pw-2" }, page(0));
    await fake.deliver({ type: "page:formDone" }, page(0));
    const [show] = sent("showSave");
    expect(show?.message.focus).toBe(undefined);
    expect(show?.message.afterLoad).toBe(undefined);
  });

  test("no content script yet: asked again, at most three times", async () => {
    await fake.deliver({ type: "page:submitted", username: "alex", password: "pw-3" }, page(0));
    let tries = 0;
    fake.setTabResponder(() => {
      tries++;
      throw new Error("Could not establish connection. Receiving end does not exist.");
    });
    vi.useFakeTimers();
    try {
      const done = onTabUpdated(TAB.id, { status: "complete" }, { url: TAB.url });
      await vi.runAllTimersAsync();
      await done;
    } finally {
      vi.useRealTimers();
    }
    expect(tries).toBe(3);
  });
});
