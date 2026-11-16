// PIN unlock (background/pin.ts, vault.ts, storage.ts): set only with the master password, kept only in session
// storage, kept through a lock, 5 wrong PINs delete it, every way out (sign-out, the timeout's sign-out, account
// switch and removal, a new master password or Secret Key, the timeout "Never", turning it off) deletes it, and a
// PIN unlock never counts as a master-password entry for passkey user verification.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { MAX_PIN_TRIES, removePin, setPin, unlockWithPin } = await import("../src/background/pin");
const { forgetServerFeatures } = await import("../src/background/api");

let fake: FakeChrome;
let server: FakeServer;
const PIN = "246810";

async function signedIn(accounts: Record<string, ReturnType<typeof accountRecord>> = { a1: accountRecord() }) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts, active: "a1" });
  // A first unlock with the master password (the offline copy then exists).
  await vault.unlock("pw");
}

const copyIn = (area: FakeChrome["session"] | FakeChrome["local"], id = "a1") => area.data.get(`pin:${id}`) as { failures: number } | undefined;

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("setting a PIN needs the vault unlocked and the right master password; the copy is in session storage only", async () => {
  await signedIn();
  await expectReject(setPin(PIN, "wrong"), (e) => /Wrong master password/.test(e.message));
  await expectReject(setPin("12345", "pw"), (e) => e.code === "bad_pin");
  await expectReject(setPin("12a456", "pw"), (e) => e.code === "bad_pin");
  expect(copyIn(fake.session)).toBeUndefined();
  await setPin(PIN, "pw");
  expect(copyIn(fake.session)?.failures).toBe(0);
  // Nothing about it on disk.
  expect([...fake.local.data.keys()].filter((k) => k.startsWith("pin"))).toStrictEqual([]);
  expect(JSON.stringify([...fake.local.data.values()])).not.toContain(PIN);
  expect((await vault.state()).pinUnlock).toBe(true);

  await vault.lockAll();
  await expectReject(setPin(PIN, "pw"), (e) => e.code === "locked");
});

test("a lock keeps the PIN copy; the PIN unlocks, without counting as a master-password entry", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.lockAll();
  expect(copyIn(fake.session)).toBeDefined();
  expect(await vault.lockStatus()).toBe("locked");
  expect(await unlockWithPin(PIN)).toStrictEqual({ unlocked: true });
  expect(await vault.lockStatus()).toBe("unlocked");
  expect(vault.owner().id).toBe("a1");
  // Passkey user verification still asks for the master password.
  expect(await vault.recentlyVerified()).toBe(false);
  expect(fake.session.data.has("verified:a1")).toBe(false);
});

test(`wrong PINs: counted before the check, ${MAX_PIN_TRIES} delete the copy; a right one resets the count`, async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.lockAll();
  expect(await unlockWithPin("000000")).toStrictEqual({ unlocked: false, triesLeft: MAX_PIN_TRIES - 1 });
  expect(copyIn(fake.session)?.failures).toBe(1);
  expect(await unlockWithPin(PIN)).toStrictEqual({ unlocked: true });
  expect(copyIn(fake.session)?.failures).toBe(0);

  await vault.lockAll();
  const answers = [];
  for (let n = 0; n < MAX_PIN_TRIES; n++) answers.push(await unlockWithPin(`11111${n}`));
  expect(answers.map((a) => (a.unlocked ? "unlocked" : a.triesLeft))).toStrictEqual([4, 3, 2, 1, 0]);
  expect(copyIn(fake.session)).toBeUndefined();
  // Now only the master password opens it.
  await expectReject(unlockWithPin(PIN), (e) => e.code === "pin_unavailable");
  expect(await vault.lockStatus()).toBe("locked");
});

test("five PINs sent at once are checked one at a time and all counted", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.lockAll();
  const answers = await Promise.all(["1", "2", "3", "4", "5"].map((d) => unlockWithPin(d.repeat(6))));
  expect(answers.map((a) => (a.unlocked ? "unlocked" : a.triesLeft)).sort()).toStrictEqual([0, 1, 2, 3, 4]);
  expect(copyIn(fake.session)).toBeUndefined();
});

test("signing out, and the timeout's sign-out, delete the PIN copy", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.logout();
  expect(copyIn(fake.session)).toBeUndefined();

  await signedIn();
  await setPin(PIN, "pw");
  await vault.logoutAll();
  expect(copyIn(fake.session)).toBeUndefined();
  await expectReject(unlockWithPin(PIN), (e) => e.code === "signed_out");
});

test("switching or removing accounts deletes the PIN copy", async () => {
  await signedIn({ a1: accountRecord(), a2: accountRecord("https://other.test", "sam@example.com") });
  await setPin(PIN, "pw");
  await vault.switchAccount("a2");
  expect(copyIn(fake.session)).toBeUndefined();

  await signedIn({ a1: accountRecord(), a2: accountRecord("https://other.test", "sam@example.com") });
  await setPin(PIN, "pw");
  // Signing out of one of several accounts removes it from the list.
  await vault.logout();
  expect(copyIn(fake.session)).toBeUndefined();
  expect(Object.keys(fake.local.data.get("accounts") as object)).toStrictEqual(["a2"]);
});

test("a new master password or Secret Key (a different bundle from the server) deletes the PIN copy", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.sync();
  expect(copyIn(fake.session), "the same bundle keeps it").toBeDefined();
  server.bundle = { ...server.bundle, password: "new-pw", kdf: { salt: "new" } };
  server.revision++;
  await vault.sync();
  await new Promise((r) => setTimeout(r, 10));
  expect(copyIn(fake.session)).toBeUndefined();
});

test('the timeout "Never" deletes the PIN copy, and a PIN can\'t be set with it', async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await fake.local.set({ settings: { vaultTimeout: "never" } });
  await vault.persistForNever();
  expect(copyIn(fake.session)).toBeUndefined();
  await expectReject(setPin(PIN, "pw"), (e) => e.code === "bad_pin");
  expect((await vault.state()).pinUnlock).toBe(false);
});

test("turning PIN unlock off deletes the copy", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await removePin();
  expect(copyIn(fake.session)).toBeUndefined();
  expect((await vault.state()).pinUnlock).toBe(false);
});

test("the PIN copy can't be used for another account, and is gone with the browser session", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  await vault.lockAll();
  // A browser restart empties session storage.
  fake.session.data.clear();
  await expectReject(unlockWithPin(PIN), (e) => e.code === "pin_unavailable");
  expect(await vault.ensureUnlocked()).toBe(false);
});

test("the stored copy: the core's re-wrapped bundle (no Secret Key) and the account bundle it came from", async () => {
  await signedIn();
  await setPin(PIN, "pw");
  const stored = fake.session.data.get("pin:a1") as { wrapped: Record<string, unknown>; base: Record<string, unknown> };
  expect(stored.base).toStrictEqual(sessionKeys().bundle);
  expect(stored.wrapped.secret_key_enabled).toBe(false);
  expect(stored.wrapped.kdf, "a new salt").not.toStrictEqual(stored.base.kdf);
  await vault.lockAll();
  expect(await unlockWithPin("123456")).toMatchObject({ unlocked: false });
});
