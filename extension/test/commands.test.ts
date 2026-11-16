// Keyboard commands (background/commands.ts): the fill shortcut fills the login used last and walks through the
// page's logins when pressed again within 5 seconds on the same tab; locked, it waits for the unlock; "Copy a
// strong password" uses the saved generator options; "Lock" locks; the notes say what was copied, never the value.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { afterUnlock, CYCLE_MS, clearsIn, copiedText, runCommand } = await import("../src/background/commands");
const { markUsed } = await import("../src/background/last-used");

let fake: FakeChrome;
const TAB = { id: 1, url: "https://example.com/login", windowId: 1, active: true };

const login = (name: string) =>
  JSON.stringify({
    name,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: name.toLowerCase(), password: `pw-${name}`, urls: [{ url: "https://example.com", match: "domain" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });

async function signedIn(names: string[], unlocked = true) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  const server = fakeServer();
  server.items = names.map((n, i) => ({ id: `i${i + 1}`, vault_id: "v-own", item_key: `own-1:${i}`, data: login(n), revision: 1, deleted_at: null }));
  vi.stubGlobal("fetch", server.fetch);
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  fake.tabs.set(TAB.id, { ...TAB });
  fake.tabs.set(2, { id: 2, url: "https://example.com/login", windowId: 1 });
  fake.setTabResponder((s) => (s.message.type === "fill" ? { filled: true } : undefined));
  if (unlocked) {
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
  }
}

const filledUsers = () => fake.sentToTabs.filter((s) => s.message.type === "fill").map((s) => s.message.username);
const press = (tab = TAB) => runCommand("autofill", { ...tab } as chrome.tabs.Tab);

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("the fill shortcut: the login used last, then the next ones on presses within 5 seconds", async () => {
  await signedIn(["Alpha", "Beta", "Gamma"]);
  await markUsed("a1", "i3", 1000);
  await markUsed("a1", "i1", 500);
  let now = Date.now();
  vi.spyOn(Date, "now").mockImplementation(() => now);
  await press();
  now += 1000;
  await press();
  now += 1000;
  await press();
  now += 1000;
  await press();
  expect(filledUsers()).toStrictEqual(["gamma", "alpha", "beta", "gamma"]);
  // A pause longer than CYCLE_MS starts again from the login used last.
  now += CYCLE_MS + 1;
  await press();
  expect(filledUsers().at(-1)).toBe("gamma");
});

test("the fill shortcut on another tab starts again from the login used last", async () => {
  await signedIn(["Alpha", "Beta"]);
  await markUsed("a1", "i2");
  await press();
  await press({ ...TAB, id: 2 });
  expect(filledUsers()).toStrictEqual(["beta", "beta"]);
});

test("the fill shortcut while locked: opens PassAuth, and fills the login used last right after the unlock", async () => {
  await signedIn(["Alpha", "Beta"], false);
  await markUsed("a1", "i2");
  await press();
  expect(fake.action.popupOpened).toBe(1);
  expect(filledUsers()).toStrictEqual([]);
  await vault.unlock("pw");
  // Several logins: the shortcut (unlike the menu's "Unlock to fill…") still fills the one used last.
  expect(await afterUnlock()).toStrictEqual({ filled: true });
  expect(filledUsers()).toStrictEqual(["beta"]);
});

test("the fill shortcut with no login for the page opens PassAuth", async () => {
  await signedIn([]);
  await press();
  expect(fake.action.popupOpened).toBe(1);
});

test("'Copy a strong password': generated with the saved options, copied, and a note in the page", async () => {
  await signedIn([]);
  await runCommand("generate_password", { ...TAB } as chrome.tabs.Tab);
  expect(fake.runtimeMessages.filter((r: any) => r?.type === "offscreen:copy").map((r: any) => r.text)).toStrictEqual(["generated-password"]);
  expect(fake.sentToTabs.filter((s) => s.message.type === "toast").map((s) => s.message.text)).toStrictEqual(["Strong password copied. It clears in 30 seconds."]);
});

test("'Lock' locks every account", async () => {
  await signedIn(["Alpha"]);
  await runCommand("lock");
  expect(await vault.lockStatus()).toBe("locked");
});

test("the notes name what was copied and the delay, never the value", () => {
  expect(clearsIn(10)).toBe("10 seconds");
  expect(clearsIn(60)).toBe("1 minute");
  expect(clearsIn(300)).toBe("5 minutes");
  expect(copiedText("password", 30)).toBe("Password copied. It clears in 30 seconds.");
  expect(copiedText("totp", 0)).toBe("Verification code copied.");
});
