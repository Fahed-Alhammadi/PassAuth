// C5: what a service-worker wake costs. Concurrent requests share one key restore and one decrypt of the offline
// copy (no /sync); syncs are coalesced; the toolbar badge and the inline menu count logins from the match index
// without opening the vault; the lock screen reads "needs a Secret Key" from the account record.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { deferred } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const { control, FakeVaultKey } = await import("./fake-core");
const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { countMatching } = await import("../src/background/matching");

let fake: FakeChrome;
let server: FakeServer;

const login = (name: string, url: string) =>
  JSON.stringify({
    name,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: "alex", password: `pw-${name}`, urls: [{ url, match: "domain" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });

/** Signed in with two logins on the server; nothing loaded in this "worker" yet. */
async function signedIn() {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.items = [
    { id: "i1", vault_id: "v-own", item_key: "own-1:1", data: login("Example", "https://example.com"), revision: 1, deleted_at: null },
    { id: "i2", vault_id: "v-own", item_key: "own-1:2", data: login("Other", "https://other.test"), revision: 1, deleted_at: null },
  ];
  vi.stubGlobal("fetch", server.fetch);
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
}

const fullSyncs = () => server.requests.filter((r) => r.path === "/sync").length;

beforeEach(() => {
  vi.unstubAllGlobals();
  control.restored = 0;
});

test("three concurrent ensureUnlocked() after a worker restart: one key restore, one decrypt of the offline copy, no /sync", async () => {
  await signedIn();
  // The offline copy from an earlier run of the worker.
  await storage.syncCache.set("a1", {
    revision: 1,
    user: { id: "u1", email: "alex@example.com", name: "Alex", email_verified: true },
    bundle: sessionKeys().bundle as never,
    vaults: server.vaults,
    items: server.items as never,
  });
  const decrypt = vi.spyOn(FakeVaultKey.prototype, "decryptItem");
  expect(await Promise.all([vault.ensureUnlocked(), vault.ensureUnlocked(), vault.ensureUnlocked()])).toStrictEqual([true, true, true]);
  // A fourth one right after shares the same load.
  expect(await vault.ensureUnlocked()).toBe(true);
  await new Promise((r) => setTimeout(r, 10));
  expect(control.restored, "keys restored once").toBe(1);
  expect(decrypt, "each item decrypted once").toHaveBeenCalledTimes(2);
  expect(fullSyncs(), "no full sync: only the revision check").toBe(0);
  expect(server.requests.filter((r) => r.path === "/sync/revision")).toHaveLength(1);
  expect(
    vault
      .allEntries()
      .map((e) => e.id)
      .sort(),
  ).toStrictEqual(["i1", "i2"]);
});

test("a request that arrives while the vault is opening waits for that open: one read of the offline copy, one decrypt", async () => {
  await signedIn();
  await storage.syncCache.set("a1", {
    revision: 1,
    user: { id: "u1", email: "alex@example.com", name: "Alex", email_verified: true },
    bundle: sessionKeys().bundle as never,
    vaults: server.vaults,
    items: server.items as never,
  });
  const copy = await storage.syncCache.get("a1");
  const held = deferred<typeof copy>();
  const read = vi.spyOn(storage.syncCache, "get").mockImplementation(() => held.promise);
  const decrypt = vi.spyOn(FakeVaultKey.prototype, "decryptItem");
  const first = vault.ensureUnlocked();
  // The keys are restored and the offline copy is being read: later requests find the keys loaded but the vault not yet open.
  while (!read.mock.calls.length) await new Promise((r) => setTimeout(r, 1));
  const later = [vault.ensureUnlocked(), vault.ensureUnlocked()];
  // Let them get as far as they can while the read is still held.
  await new Promise((r) => setTimeout(r, 20));
  held.resolve(copy);
  expect(await Promise.all([first, ...later])).toStrictEqual([true, true, true]);
  expect(read).toHaveBeenCalledTimes(1);
  expect(decrypt).toHaveBeenCalledTimes(2);
  expect(fullSyncs()).toBe(0);
});

test("without an offline copy, concurrent first loads share one /sync", async () => {
  await signedIn();
  expect(await Promise.all([vault.ensureUnlocked(), vault.ensureUnlocked(), vault.ensureUnlocked()])).toStrictEqual([true, true, true]);
  expect(fullSyncs()).toBe(1);
});

test("syncs are coalesced: calls during a sync share one follow-up that starts after it", async () => {
  await signedIn();
  expect(await vault.ensureUnlocked()).toBe(true);
  const before = fullSyncs();
  await Promise.all([vault.sync(), vault.sync(), vault.sync(), vault.sync()]);
  expect(fullSyncs() - before, "the running one and one follow-up").toBe(2);
  // A change made while a sync is running is seen by whoever asked after it.
  const running = vault.sync();
  server.editElsewhere("i1", { name: "Renamed" });
  await Promise.all([running, vault.sync()]);
  expect(vault.getEntry("i1")?.item.name).toBe("Renamed");
});

test("the badge and inline-menu count comes from the match index after a worker restart: no key restore, no decrypt", async () => {
  await signedIn();
  expect(await vault.ensureUnlocked()).toBe(true);
  // What the index holds: ids, websites, whether the login is the user's own. No names, user names or passwords.
  const index = fake.session.data.get("index:a1") as { logins: Record<string, unknown>[] };
  expect(index.logins.map((l) => Object.keys(l).sort())).toStrictEqual([
    ["id", "personal", "urls"],
    ["id", "personal", "urls"],
  ]);
  expect(JSON.stringify(index)).not.toContain("pw-");

  // A worker restart: the modules start empty, the session (keys, index) is still there.
  vi.resetModules();
  const restarted = await import("../src/background/matching");
  const restartedVault = await import("../src/background/vault");
  expect(restartedVault.owner().id, "a fresh worker has no keys loaded").toBe("");
  const freshCore = await import("./fake-core");
  freshCore.control.restored = 0;
  control.restored = 0;
  const decrypt = vi.spyOn(freshCore.FakeVaultKey.prototype, "decryptItem");
  const decryptOld = vi.spyOn(FakeVaultKey.prototype, "decryptItem");
  const requests = server.requests.length;
  expect(await restarted.countMatching("https://www.example.com/login")).toBe(1);
  expect(await restarted.countMatching("https://nothing.test/")).toBe(0);
  expect(freshCore.control.restored + control.restored, "no key restore").toBe(0);
  expect(decrypt.mock.calls.length + decryptOld.mock.calls.length, "no decrypt").toBe(0);
  expect(server.requests.length, "no request to the server").toBe(requests);
  expect(restartedVault.owner().id, "still no keys loaded").toBe("");
});

test("a lock takes the match index with the keys; locked, nothing is counted", async () => {
  await signedIn();
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(fake.session.data.has("index:a1")).toBe(true);
  expect(await countMatching("https://example.com/")).toBe(1);
  await vault.lockAll();
  expect(fake.session.data.has("index:a1")).toBe(false);
  expect(await countMatching("https://example.com/")).toBe(null);
});

test('the lock screen reads "needs a Secret Key" from the account record, not from the offline copy', async () => {
  await signedIn();
  server.bundle = { account_id: "acc-1", password: "pw", secret_key_enabled: true };
  await fake.session.set({ "unlocked:a1": sessionKeys(server.bundle) });
  expect(await vault.ensureUnlocked()).toBe(true);
  await new Promise((r) => setTimeout(r, 10));
  expect((fake.local.data.get("accounts") as Record<string, { secretKeyEnabled?: boolean }>).a1?.secretKeyEnabled).toBe(true);
  await vault.lockAll();
  const read = vi.spyOn(storage.syncCache, "get");
  const state = await vault.state();
  expect([state.status, state.secretKeyRequired]).toStrictEqual(["locked", true]);
  expect(read).not.toHaveBeenCalled();
});

test('C6: unlock with the timeout "never" can\'t put keys back on disk after a lock that came in between', async () => {
  await signedIn();
  await fake.local.set({ settings: { vaultTimeout: "never" } });
  expect(await vault.ensureUnlocked()).toBe(true);
  // A settings save (persistForNever) and a lock at the same moment: the lock wins.
  await Promise.all([vault.persistForNever(), vault.lockAll()]);
  expect((fake.local.data.get("accounts") as Record<string, { persistedKeys: unknown }>).a1?.persistedKeys).toBe(null);
});
