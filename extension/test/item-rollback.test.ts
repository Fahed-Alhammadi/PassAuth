// Item rollback detection in the service worker (background/item-revs.ts used by background/vault.ts): the highest item
// edit counter (`rev`, inside the ciphertext) seen per item is kept with the offline copy; a server that sends an older
// version is caught on full, delta and live syncs, the newer copy this browser had is kept (and can be edited), the item
// and the vault list carry the warning, equal counters with other content are accepted, and items gone for good are
// forgotten.

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

beforeEach(() => {
  vi.unstubAllGlobals();
});

for (const [name, features] of [
  ["delta sync", DELTA],
  ["full sync (older server)", OLD],
] as const) {
  test(`${name}: an older version from the server keeps the newer copy, marks the item and says so; the counter is never lowered`, async () => {
    await signedIn([...features]);
    expect((await stored())?.itemRevs).toStrictEqual({ i1: 3, i2: 1 });
    expect(vault.rollbackSummary()).toBe(null);
    rollBack("i1", login("old-password", 2));
    await vault.sync();
    expect(password("i1")).toBe("new-password");
    expect(vault.rolledBack("i1")).toBe(true);
    expect(vault.rolledBack("i2")).toBe(false);
    expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_KEPT_TEXT);
    // The offline copy keeps the newer ciphertext (with the server's revision) and the counter stays 3.
    const copy = await stored();
    expect(copy?.itemRevs?.i1).toBe(3);
    expect(copy?.rolledBack).toStrictEqual({ i1: "kept" });
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
  expect((await stored())?.itemRevs?.i1).toBe(4);
});

test("with no newer copy it can open (the vault key was replaced meanwhile), the server's version is shown, marked", async () => {
  await signedIn(DELTA);
  server.rotate("v-own");
  rollBack("i1", login("old-password", 2));
  await vault.sync();
  expect(password("i1")).toBe("old-password");
  expect(vault.rolledBack("i1")).toBe(true);
  expect(vault.rollbackSummary()?.text).toBe(ROLLBACK_TEXT);
  expect((await stored())?.itemRevs?.i1).toBe(3);
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

test("items deleted for good are forgotten; this browser's own writes are remembered", async () => {
  await signedIn(DELTA);
  server.deleteElsewhere("i2");
  await vault.sync();
  expect((await stored())?.itemRevs).toStrictEqual({ i1: 3 });
  const id = await vault.createItem(JSON.parse(login("fresh", 0)));
  expect((await stored())?.itemRevs?.[id]).toBe(1);
});

test("the popup's item page and list carry the warnings", () => {
  expect(ROLLBACK_ITEM_TEXT).toBe("Your server sent an older version of this item.");
  expect(ROLLBACK_KEPT_TEXT).toBe("Your server sent older versions of some items. PassAuth kept the newer copies it had.");
  expect(ROLLBACK_TEXT).toBe("Your server sent older versions of some items.");
});
