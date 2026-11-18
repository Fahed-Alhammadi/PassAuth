// Item rollback detection in the service worker (background/item-revs.ts used by background/vault.ts): the highest item
// edit counter (`rev`, inside the ciphertext) seen per item is kept in the account's device memory (its own record,
// which outlives the offline copy: a "log out" timeout doesn't remove it); a server that sends an older version is
// caught on full, delta and live syncs, the newer copy this browser had is kept (and can be edited), the item and the
// vault list carry the warning until the row is rewritten, equal counters with other content are accepted, and an
// item is forgotten only when its absence is proven (an "ok" manifest), never because a server left it out.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures } = await import("../src/background/api");
const { ROLLBACK_ITEM_TEXT, ROLLBACK_KEPT_TEXT, ROLLBACK_TEXT } = await import("../src/background/item-revs");

const DELTA = ["key_epoch", "idempotent_create", "error_codes", "delta_sync"];
const OLD = ["key_epoch", "idempotent_create", "error_codes"];

let fake: FakeChrome;
let server: FakeServer;

const login = (password: string, rev: number) =>
  JSON.stringify({
    name: "Bank",
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: "alex", password, urls: [{ url: "https://bank.example", match: "domain" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
    rev,
  });

async function signedIn(features: string[]) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = features;
  server.addElsewhere("i1", "v-own", login("new-password", 3));
  server.addElsewhere("i2", "v-own", login("other", 1));
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

/** The server puts back an older ciphertext of `id` (as a new write, so syncs bring it). */
function rollBack(id: string, data: string) {
  server.editElsewhere(id, {});
  server.items.find((i) => i.id === id)!.data = data;
}

const password = (id: string) => vault.getEntry(id)?.item.login?.password;
const stored = () => storage.syncCache.get("a1");
/** The account's device memory as stored (its own record, not the offline copy). */
const memory = async () => ((await storage.deviceMemory.read("https://vault.test", "u-1")) ?? {}) as { itemRevs?: Record<string, number>; rolledBack?: Record<string, string> };
const MANIFEST = [...DELTA, "vault_manifest"];

beforeEach(() => {
  vi.unstubAllGlobals();
});

for (const [name, features] of [
  ["delta sync", DELTA],
  ["full sync (older server)", OLD],
] as const) {
  test(`${name}: an older version from the server keeps the newer copy, marks the item and says so; the counter is never lowered`, async () => {
    await signedIn([...features]);
    expect((await memory()).itemRevs).toStrictEqual({ i1: 3, i2: 1 });
    expect((await stored())?.itemRevs, "not in the offline copy").toBeUndefined();
    expect(vault.rollbackSummary()).toBe(null);
    rollBack("i1", login("old-password", 2));
    await vault.sync();
    expect(password("i1")).toBe("new-password");
    expect(vault.rolledBack("i1")).toBe(true);
    expect(vault.rolledBack("i2")).toBe(false);
    expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_KEPT_TEXT);
    // The offline copy keeps the newer ciphertext (with the server's revision) and the counter stays 3.
    const copy = await stored();
    expect((await memory()).itemRevs?.i1).toBe(3);
    expect((await memory()).rolledBack).toStrictEqual({ i1: "kept" });
    // What the server sent is noted beside the rows, never on the row.
    expect(Object.keys(copy?.served ?? {})).toStrictEqual(["i1"]);
    expect(copy?.items.some((r) => "served_sha256" in r)).toBe(false);
    const row = copy?.items.find((r) => r.id === "i1");
    expect(JSON.parse(row!.data).login.password).toBe("new-password");
    expect(row?.revision).toBe(server.items.find((i) => i.id === "i1")!.revision);
    // Another sync of the same answer: still the newer copy.
    await vault.sync();
    expect(password("i1")).toBe("new-password");
  });
}

test("an edit made from the kept copy goes through (the server's revision) and counts up from the higher counter: the mark goes", async () => {
  await signedIn(DELTA);
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  const e = vault.getEntry("i1")!;
  await vault.updateItem(e, { ...e.item, notes: "checked" });
  const sent = JSON.parse(server.items.find((i) => i.id === "i1")!.data);
  expect(sent.login.password).toBe("new-password");
  expect(sent.rev).toBe(4);
  expect(vault.rolledBack("i1")).toBe(false);
  expect(vault.rollbackSummary()).toBe(null);
  expect((await memory()).itemRevs?.i1).toBe(4);
  expect((await stored())?.served, "the row is this browser's own write now").toBeUndefined();
});

test("with no newer copy it can open (the vault key was replaced meanwhile), the server's version is shown, marked", async () => {
  await signedIn(DELTA);
  server.rotate("v-own");
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  expect(password("i1")).toBe("old-password");
  expect(vault.rolledBack("i1")).toBe(true);
  expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_TEXT);
  expect((await memory()).itemRevs?.i1).toBe(3);
  // Once the server sends a newer version again, the mark goes.
  server.editElsewhere("i1", { rev: 5, login: { username: "alex", password: "newest", urls: [], totp: null, passkeys: [] } });
  await vault.sync();
  expect(password("i1")).toBe("newest");
  expect(vault.rolledBack("i1")).toBe(false);
});

test("the same counter with other content (an edit by an app from before the counter) is accepted, not marked", async () => {
  await signedIn(DELTA);
  server.editElsewhere("i2", { notes: "edited by an older app" });
  await vault.sync();
  expect(vault.getEntry("i2")?.item.notes).toBe("edited by an older app");
  expect(vault.rolledBack("i2")).toBe(false);
});

test("the memory survives a lock (offline copy): a rollback after unlocking is still caught, and the mark is still shown", async () => {
  await signedIn(DELTA);
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(password("i1")).toBe("new-password");
  expect(vault.rolledBack("i1")).toBe(true);
  // A new rollback of the other item, after the unlock.
  rollBack("i2", login("older", 0));
  await vault.sync();
  expect(vault.rolledBack("i2")).toBe(true);
  expect(password("i2")).toBe("other");
});

test("an item is forgotten only when a checked manifest proves it gone; this browser's own writes are remembered", async () => {
  // A vault with a manifest: the delete came with the vault's next manifest, which checks out. Gone for certain.
  await signedIn(MANIFEST);
  server.startManifestElsewhere("v-own");
  await vault.sync();
  server.deleteElsewhere("i2");
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect((await memory()).itemRevs).toStrictEqual({ i1: 3 });
  expect((await stored())?.stash).toBeUndefined();
  const id = await vault.createItem(JSON.parse(login("fresh", 0)));
  expect((await memory()).itemRevs?.[id]).toBe(1);
  // No manifest: a server's "deleted" proves nothing. The counter stays (and the row is kept aside).
  await signedIn(DELTA);
  server.deleteElsewhere("i2");
  await vault.sync();
  expect(vault.getEntry("i2")).toBeUndefined();
  expect((await memory()).itemRevs).toStrictEqual({ i1: 3, i2: 1 });
  expect((await stored())?.stash?.map((r) => r.id)).toStrictEqual(["i2"]);
});

test("REVIEW (hide once, then serve the old copy): an item a server leaves out and brings back in an older version is still caught, and the newer copy this browser had is kept", async () => {
  for (const how of ["the item", "its whole vault"] as const) {
    await signedIn(DELTA);
    const hidden = server.items.find((i) => i.id === "i1")!;
    const vaultRow = server.vaults[0]!;
    // Step 1: the server leaves it out of one answer.
    if (how === "the item") server.deleteElsewhere("i1");
    else {
      server.vaults = [];
      server.revision++;
    }
    await vault.sync();
    expect(vault.getEntry("i1"), how).toBeUndefined();
    expect((await memory()).itemRevs?.i1, `${how}: the counter is kept`).toBe(3);
    // Also across a lock (the copy this browser had is kept aside in the offline copy).
    await vault.lockAll();
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
    // Step 2: it comes back in an older version.
    if (how === "its whole vault") server.vaults = [vaultRow];
    server.items = server.items.filter((i) => i.id !== "i1");
    server.items.push({ ...hidden, data: login("old-password", 2), revision: ++server.revision, seq: server.bump("v-own") });
    await vault.sync();
    expect(vault.rolledBack("i1"), how).toBe(true);
    expect(password("i1"), `${how}: the newer copy is shown`).toBe("new-password");
    expect(vault.rollbackSummary()?.text, how).toBe(ROLLBACK_KEPT_TEXT);
    expect((await memory()).itemRevs?.i1, how).toBe(3);
    expect((await stored())?.stash, `${how}: it is a row again`).toBeUndefined();
  }
});

test("REVIEW (the 'log out' timeout): what this browser remembers outlives the offline copy, so a rollback after signing in again is still caught", async () => {
  await signedIn(DELTA);
  await vault.logoutAll();
  expect(await stored(), "the offline copy is gone").toBeUndefined();
  expect((await memory()).itemRevs, "the memory isn't").toStrictEqual({ i1: 3, i2: 1 });
  // Signed in again; the server now serves an older version of an item.
  rollBack("i1", login("old-password", 2));
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(vault.rolledBack("i1")).toBe(true);
  expect(password("i1"), "no newer copy is left to show").toBe("old-password");
  expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_TEXT);
  expect((await memory()).itemRevs?.i1, "never lowered").toBe(3);
  // An explicit sign-out of the only account keeps it too; removing the account from the browser removes it.
  await vault.logout();
  expect((await memory()).itemRevs?.i1).toBe(3);
  await fake.local.set({ accounts: { a1: { ...accountRecord(), userId: "u-1" } }, active: "a1" });
  await storage.local.removeAccount("a1");
  expect(await storage.deviceMemory.read("https://vault.test", "u-1")).toBeUndefined();
});

test("a kept newer copy stays marked: across later syncs, other writes, a lock, and a sign-out it becomes 'older'; until the row is rewritten", async () => {
  await signedIn(DELTA);
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  const marked = () => [vault.rolledBack("i1"), password("i1"), vault.rollbackSummary()?.text];
  const kept = [true, "new-password", ROLLBACK_KEPT_TEXT];
  expect(marked()).toStrictEqual(kept);
  // Another sync that brings other changes, and one that brings the same old row again.
  server.editElsewhere("i2", { notes: "x" });
  await vault.sync();
  expect(marked()).toStrictEqual(kept);
  server.editElsewhere("i1", {});
  await vault.sync();
  expect(marked()).toStrictEqual(kept);
  // An own write of another item.
  const other = vault.getEntry("i2")!;
  await vault.updateItem(other, { ...other.item, notes: "mine" });
  expect(marked()).toStrictEqual(kept);
  // A lock and unlock (from the offline copy), and the full sync of an older server after it.
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(marked()).toStrictEqual(kept);
  // The server serves that version (or a newer one) again: the mark goes.
  server.editElsewhere("i1", { rev: 3, login: JSON.parse(login("new-password", 3)).login });
  await vault.sync();
  expect(marked()).toStrictEqual([false, "new-password", undefined]);
  expect((await stored())?.served).toBeUndefined();
});

test("FINAL REVIEW C1: an old version served first in the trash (valid key), then live with a damaged key, is marked 'older' like the same answer with a good key; a damaged key on the current version marks nothing", async () => {
  const item = () => server.items.find((i) => i.id === "i1")!;
  const again = () => ({ revision: ++server.revision, seq: server.bump("v-own") });
  for (const key of ["damaged", "good"] as const) {
    // A server that sends the trash whole (as any server can, whatever was asked for).
    await signedIn(OLD);
    server.editElsewhere("i1", { rev: 5, login: JSON.parse(login("newest", 5)).login });
    await vault.sync();
    expect((await memory()).itemRevs?.i1).toBe(5);
    const mine = item().item_key;
    // Step 1: the item is in the trash, in an old version that its key opens. Nothing to show, the counter stays.
    Object.assign(item(), { data: login("old-password", 3), deleted_at: 1_700_000_000, ...again() });
    await vault.sync();
    expect(vault.getEntry("i1"), key).toBeUndefined();
    expect((await memory()).itemRevs?.i1, key).toBe(5);
    // Step 2: live again, the same old data.
    Object.assign(item(), { deleted_at: null, ...(key === "damaged" ? { item_key: "not-the-key" } : {}), ...again() });
    await vault.sync();
    expect(password("i1"), `${key}: no newer copy is left to show`).toBe("old-password");
    expect(vault.rolledBack("i1"), key).toBe(true);
    expect(vault.rollbackSummary()?.text, key).toBe(ROLLBACK_TEXT);
    expect((await memory()).rolledBack, key).toStrictEqual({ i1: "older" });
    expect((await memory()).itemRevs?.i1, `${key}: never lowered`).toBe(5);
    expect((await stored())?.items.find((r) => r.id === "i1")?.item_key, `${key}: the copy keeps a key that opens the row`).toBe(mine);
    expect(vault.otherItems(), key).toStrictEqual([]);
    // Still marked after a lock and unlock, and after the same answer again.
    await vault.lockAll();
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
    await vault.sync();
    expect([vault.rolledBack("i1"), password("i1")], key).toStrictEqual([true, "old-password"]);
  }
});

test("FINAL REVIEW C1: a damaged key still can't lose a newer copy this browser kept, and clears no mark the data doesn't clear", async () => {
  await signedIn(OLD);
  const item = () => server.items.find((i) => i.id === "i1")!;
  // Honest T1(a): the current version with a damaged key. Shown with this browser's key, not marked, not listed.
  Object.assign(item(), { item_key: "not-the-key", revision: ++server.revision });
  await vault.sync();
  expect([password("i1"), vault.rolledBack("i1"), vault.rollbackSummary()]).toStrictEqual(["new-password", false, null]);
  expect(vault.otherItems()).toStrictEqual([]);
  expect([(await memory()).itemRevs, (await memory()).rolledBack]).toStrictEqual([{ i1: 3, i2: 1 }, undefined]);
  // An older version (good key): the newer copy is kept and marked.
  await signedIn(OLD);
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  expect([password("i1"), vault.rollbackSummary()?.text]).toStrictEqual(["new-password", ROLLBACK_KEPT_TEXT]);
  // The same old version again with a damaged key: the kept copy stays, and stays marked.
  Object.assign(item(), { item_key: "not-the-key", revision: ++server.revision });
  await vault.sync();
  expect(password("i1")).toBe("new-password");
  expect(vault.rolledBack("i1")).toBe(true);
  expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_KEPT_TEXT);
  expect(vault.otherItems()).toStrictEqual([]);
  expect([(await memory()).itemRevs?.i1, (await memory()).rolledBack]).toStrictEqual([3, { i1: "kept" }]);
  // An older version shown marked (no newer copy: the vault key was replaced), then served with a damaged key: marked still.
  await signedIn(OLD);
  server.rotate("v-own");
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  expect([password("i1"), vault.rolledBack("i1")]).toStrictEqual(["old-password", true]);
  Object.assign(item(), { item_key: "not-the-key", revision: ++server.revision });
  await vault.sync();
  expect([password("i1"), vault.rolledBack("i1")]).toStrictEqual(["old-password", true]);
  expect((await memory()).rolledBack).toStrictEqual({ i1: "older" });
});

test("the popup's item page and list carry the warnings", () => {
  expect(ROLLBACK_ITEM_TEXT).toBe("Your server sent an older version of this item.");
  expect(ROLLBACK_KEPT_TEXT).toBe("Your server sent older versions of some items. PassAuth kept the newer copies it had.");
  expect(ROLLBACK_TEXT).toBe("Your server sent older versions of some items.");
});
