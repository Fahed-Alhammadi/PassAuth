// Locking and restoring keys (background/vault.ts): S9 (a lock during a restore sticks), S11 (Lock locks every
// account) and S4's "recently verified" (only a master password typed in this browser session counts).

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, fakeServer, sessionKeys } from "./fake-server";
import { deferred } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const { control } = await import("./fake-core");
const vault = await import("../src/background/vault");

let fake: FakeChrome;
const pause = () => new Promise((r) => setTimeout(r, 10));

beforeEach(async () => {
  vi.unstubAllGlobals();
  fake = installChrome();
  vi.stubGlobal("fetch", fakeServer().fetch);
});

// Must run first: it holds the core's one-time initialisation open.
test("S9: a lock while a restore is still waiting can't be undone by that restore", async () => {
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  const init = deferred();
  control.init = () => init.promise;
  const restoring = vault.ensureUnlocked();
  await pause(); // the restore read the session keys and now waits for the core
  await vault.lockAll();
  init.resolve();
  expect(await restoring).toBe(false);
  expect(control.restored, "keys never installed").toBe(0);
  expect(vault.owner().id).toBe("");
  expect(fake.session.data.has("unlocked:a1")).toBe(false);
  // A later request finds the vault locked, as the user left it.
  expect(await vault.ensureUnlocked()).toBe(false);
});

test('S9: with the timeout "never", a lock during the restore from disk doesn\'t bring the keys back', async () => {
  await fake.local.set({ accounts: { a1: { ...accountRecord(), persistedKeys: sessionKeys() } }, active: "a1", settings: { vaultTimeout: "never" } });
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  // Hold the restore after it copied the keys from disk into the session.
  const realSet = fake.chrome.storage.session.set;
  fake.chrome.storage.session.set = async (items: Record<string, unknown>) => {
    await realSet(items);
    if ("unlocked:a1" in items) await held;
  };
  const restoring = vault.ensureUnlocked();
  await pause();
  fake.chrome.storage.session.set = realSet;
  await vault.lockAll();
  release();
  expect(await restoring).toBe(false);
  expect(fake.session.data.has("unlocked:a1")).toBe(false);
  expect((fake.local.data.get("accounts") as Record<string, { persistedKeys: unknown }>).a1?.persistedKeys).toBe(null);
  expect(vault.owner().id).toBe("");
});

test("S11: Lock locks every account, not just the active one", async () => {
  await fake.local.set({ accounts: { a1: accountRecord(), a2: accountRecord("https://other.test") }, active: "a1", settings: { vaultTimeout: "never" } });
  await fake.session.set({ "unlocked:a1": sessionKeys(), "unlocked:a2": sessionKeys() });
  await fake.local.set({ accounts: { a1: { ...accountRecord(), persistedKeys: sessionKeys() }, a2: { ...accountRecord("https://other.test"), persistedKeys: sessionKeys() } } });
  expect(await vault.ensureUnlocked()).toBe(true);
  await vault.lock();
  expect([...fake.session.data.keys()].filter((k) => k.startsWith("unlocked:"))).toStrictEqual([]);
  const accounts = fake.local.data.get("accounts") as Record<string, { persistedKeys: unknown }>;
  expect([accounts.a1?.persistedKeys, accounts.a2?.persistedKeys]).toStrictEqual([null, null]);
  expect(await vault.ensureUnlocked()).toBe(false);
});

test("S4: restored keys are not a recent master-password entry; unlocking is, for 5 minutes", async () => {
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(await vault.recentlyVerified()).toBe(false);

  await vault.unlock("pw");
  expect(await vault.recentlyVerified()).toBe(true);
  const at = Date.now();
  const now = vi.spyOn(Date, "now");
  now.mockReturnValue(at + vault.VERIFIED_MS - 1000);
  expect(await vault.recentlyVerified()).toBe(true);
  now.mockReturnValue(at + vault.VERIFIED_MS + 1000);
  expect(await vault.recentlyVerified()).toBe(false);
  now.mockRestore();
});

test('S4: a lock forgets the entry; keys from disk (timeout "never") after a browser restart never count', async () => {
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1", settings: { vaultTimeout: "never" } });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await vault.unlock("pw");
  expect(await vault.recentlyVerified()).toBe(true);
  // "never": the keys are on disk too.
  expect((fake.local.data.get("accounts") as Record<string, { persistedKeys: unknown }>).a1?.persistedKeys).not.toBe(null);

  // Browser restart: session storage is empty, the worker starts again.
  fake.session.data.clear();
  await vault.lockAll().catch(() => {});
  await fake.local.set({ accounts: { a1: { ...accountRecord(), persistedKeys: sessionKeys() } } });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(await vault.recentlyVerified()).toBe(false);

  // Unlock, then lock: the entry goes with the keys.
  await vault.unlock("pw");
  expect(await vault.recentlyVerified()).toBe(true);
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(await vault.recentlyVerified()).toBe(false);
});

test("S4: checking the master password in the passkey window counts as an entry; a wrong one doesn't", async () => {
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  await expect(vault.verifyMasterPassword("wrong")).rejects.toThrow("Wrong master password or Secret Key.");
  expect(await vault.recentlyVerified()).toBe(false);
  await vault.verifyMasterPassword("pw");
  expect(await vault.recentlyVerified()).toBe(true);
});

test("C18: owner() / stillOwner() see a lock or an account switch", async () => {
  await fake.local.set({ accounts: { a1: accountRecord(), a2: accountRecord("https://other.test") }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  const o = vault.owner();
  expect(o.id).toBe("a1");
  expect(vault.stillOwner(o)).toBe(true);
  await vault.switchAccount("a2");
  expect(vault.stillOwner(o)).toBe(false);
  await vault.switchAccount("a1");
  expect(await vault.ensureUnlocked()).toBe(true);
  // Same account again, but loaded anew: a request from before still doesn't count.
  expect(vault.stillOwner(o)).toBe(false);
});
