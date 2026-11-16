// C6: data stored by older versions is moved once, behind `schemaVersion`, when the worker starts — not on reads —
// and reads wait while it happens.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";

let fake: FakeChrome;

/** A worker start: fresh modules over the same storage. */
async function start() {
  vi.resetModules();
  const migrations = await import("../src/background/migrations");
  const storage = await import("../src/background/storage");
  return { ...migrations, ...storage };
}

beforeEach(() => {
  fake = installChrome();
});

test("every step once, in order: the old top-level account, autoLockMinutes, Secret Keys by email", async () => {
  // As 0.2 left it: one account at the top level, the old timeout setting, a Secret Key by email.
  await fake.local.set({
    server: "https://vault.test",
    email: "alex@example.com",
    tokens: { access: "a", refresh: "r" },
    autoLockMinutes: 0,
    secretKeys: { "alex@example.com": "SK" },
  });
  const { migrate, local, SCHEMA_VERSION } = await start();
  await migrate();
  const l = await local.get();
  expect([l.server, l.email, l.tokens]).toStrictEqual(["https://vault.test", "alex@example.com", { access: "a", refresh: "r" }]);
  expect(Object.keys(l.accounts)).toStrictEqual([l.activeId]);
  expect(l.settings.vaultTimeout).toBe("restart");
  expect(l.secretKeys).toStrictEqual({ "https://vault.test|alex@example.com": "SK" });
  expect(fake.local.data.get("schemaVersion")).toBe(SCHEMA_VERSION);
  for (const key of ["server", "email", "tokens", "autoLockMinutes"]) expect(fake.local.data.has(key), key).toBe(false);
});

test("reads don't migrate; a worker start does it once, and later starts only read the version", async () => {
  await fake.local.set({
    accounts: { a1: { server: "https://vault.test", email: "alex@example.com", name: "", tokens: null, lastSync: 0, persistedKeys: null } },
    active: "a1",
    secretKeys: { "alex@example.com": "SK" },
  });
  let s = await start();
  expect((await s.local.get()).secretKeys, "a read leaves stored data as it is").toStrictEqual({ "alex@example.com": "SK" });
  await s.migrate();
  expect(fake.local.data.get("secretKeys")).toStrictEqual({ "https://vault.test|alex@example.com": "SK" });

  // Something older writes an email-keyed entry again: a migrated store is not touched again.
  await fake.local.set({ secretKeys: { "alex@example.com": "SK-2" } });
  s = await start();
  const set = vi.spyOn(fake.chrome.storage.local, "set");
  await s.migrate();
  expect(set).not.toHaveBeenCalled();
  expect(fake.local.data.get("secretKeys")).toStrictEqual({ "alex@example.com": "SK-2" });
});

test("a read that comes in while the migration runs waits for it", async () => {
  await fake.local.set({ server: "https://vault.test", email: "alex@example.com", tokens: { access: "a", refresh: "r" } });
  const { migrate, local } = await start();
  const migrating = migrate();
  const l = await local.get();
  await migrating;
  expect(l.server).toBe("https://vault.test");
  expect(l.activeId).not.toBe("");
});
