// API contract v2, client side (background/vault.ts, api.ts): key_epoch on writes, the vault_key_changed → sync →
// re-encrypt → retry-once path, item ids kept across retries of a create, X-PassAuth-Client on every request.

import type { Item } from "@web/lib/types";
import { beforeEach, expect, test, vi } from "vitest";
import { installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, type Recorded, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const { ApiError, forgetServerFeatures } = await import("../src/background/api");

let server: FakeServer;

const login = (name: string, password = "pw"): Item => ({
  name,
  notes: "",
  favorite: false,
  folder: null,
  tags: [],
  login: { username: "alex", password, urls: [{ url: "https://example.com", match: "default" }], totp: null, passkeys: [] },
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 0,
  updated_at: 0,
});

async function signedIn(features?: string[]) {
  const fake = installChrome();
  server = fakeServer();
  if (features) server.features = features;
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  // Drop whatever an earlier test loaded, then restore from the session like after a worker restart.
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  return fake;
}

const writes = () => server.requests.filter((r) => r.method === "POST" || r.method === "PUT");

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("every API request says which client it is", async () => {
  await signedIn();
  await vault.createItem(login("Example"));
  expect(server.requests.length).toBeGreaterThan(2);
  for (const r of server.requests) expect(r.headers["x-passauth-client"], `${r.method} ${r.path}`).toBe("extension/9.8.7");
});

test("writes carry the vault's key_epoch from /sync (servers listing the key_epoch feature)", async () => {
  await signedIn();
  const id = await vault.createItem(login("Example"));
  const created = writes().at(-1)!;
  expect([created.method, created.path, created.body.key_epoch, created.body.id]).toStrictEqual(["POST", "/items", 1, id]);
  await vault.updateItem(vault.getEntry(id)!, { ...vault.getEntry(id)!.item, notes: "changed" });
  const updated = writes().at(-1)!;
  expect([updated.method, updated.body.key_epoch]).toStrictEqual(["PUT", 1]);
});

test("create after the vault key was replaced: 409 vault_key_changed → sync → re-encrypted with the new key, same id, once", async () => {
  await signedIn();
  await vault.createItem(login("First"));
  server.rotate("v-own"); // a member was removed elsewhere; this client still has epoch 1
  const id = await vault.createItem(login("Second"));
  const posts = server.requests.filter((r) => r.method === "POST" && r.path === "/items");
  const [refused, retried] = posts.slice(-2) as [Recorded, Recorded];
  expect([refused.body.key_epoch, retried.body.key_epoch]).toStrictEqual([1, 2]);
  expect(refused.body.id).toBe(id);
  expect(retried.body.id).toBe(id);
  // Encrypted under the new key (the fake core tags item keys with the vault key).
  expect(retried.body.key.startsWith("v-own-key-2:")).toBe(true);
  // A sync came in between.
  const between = server.requests.slice(server.requests.indexOf(refused), server.requests.indexOf(retried));
  expect(between.some((r) => r.path === "/sync")).toBe(true);
  expect(vault.getEntry(id)?.item.name).toBe("Second");
  expect(server.items.filter((i) => i.id === id)).toHaveLength(1);
});

test("update after the vault key was replaced: synced, the same change applied to the re-encrypted copy, once", async () => {
  await signedIn();
  const id = await vault.createItem(login("Example", "old"));
  const stale = vault.getEntry(id)!;
  server.rotate("v-own");
  await vault.updateItem(stale, { ...stale.item, login: { ...stale.item.login!, password: "new" } });
  const puts = server.requests.filter((r) => r.method === "PUT");
  expect(puts.map((r) => r.body.key_epoch)).toStrictEqual([1, 2]);
  const entry = vault.getEntry(id)!;
  expect(entry.item.login?.password).toBe("new");
  // The old password went to the history once, not twice.
  expect(entry.item.password_history.map((h) => h.password)).toStrictEqual(["old"]);
});

test("update after a key change when the item was also edited elsewhere: refused, nothing overwritten", async () => {
  await signedIn();
  const id = await vault.createItem(login("Example", "old"));
  const stale = vault.getEntry(id)!;
  server.editElsewhere(id, { notes: "edited on the phone" });
  server.rotate("v-own");
  await expectReject(vault.updateItem(stale, { ...stale.item, login: { ...stale.item.login!, password: "new" } }), (e) => e instanceof ApiError && e.code === "revision_conflict");
  expect(JSON.parse(server.items.find((i) => i.id === id)!.data).notes).toBe("edited on the phone");
  expect(server.requests.filter((r) => r.method === "PUT")).toHaveLength(1);
});

test("a second key change during the retry is not retried again", async () => {
  await signedIn();
  server.rotate("v-own");
  // Every create is refused as if the key kept changing.
  server.handlers["POST /items"] = () => ({ status: 409, body: { error: "vault_key_changed", message: "the vault key was replaced" } });
  await expectReject(vault.createItem(login("Example")), (e) => e instanceof ApiError && e.code === "vault_key_changed");
  expect(server.requests.filter((r) => r.method === "POST" && r.path === "/items")).toHaveLength(2);
});

test("a create that timed out but reached the server waits as an offline change and isn't saved twice", async () => {
  await signedIn();
  const id = crypto.randomUUID();
  server.dropReply.add("POST /items");
  // No answer: the save works for the user and waits (offline changes), shown with its marker.
  expect(await vault.createItem(login("Example"), undefined, id)).toBe(id);
  expect(server.items).toHaveLength(1);
  expect(vault.getEntry(id)?.item.name).toBe("Example");
  // The next sync that checks out sends it: the server already has exactly what was sent, so nothing is stored again.
  await vault.sync();
  await vault.sendOfflineChanges();
  expect(server.items).toHaveLength(1);
  expect(vault.offlineSummary()).toBeNull();
  // Trying again (the save prompt or the editor keeps the id): the copy that arrived is used.
  expect(await vault.createItem(login("Example"), undefined, id)).toBe(id);
  expect(server.items).toHaveLength(1);
  expect(vault.getEntry(id)?.item.name).toBe("Example");
});

test("retrying with the same id after the item was changed: the waiting create takes the new item and brings the server's copy up to date", async () => {
  await signedIn(["key_epoch"]); // a server without error codes: says "item id already exists"
  const id = crypto.randomUUID();
  server.dropReply.add("POST /items");
  await vault.createItem(login("Example", "first"), undefined, id);
  await vault.createItem(login("Example", "second"), undefined, id);
  await vault.sync();
  await vault.sendOfflineChanges();
  expect(server.items).toHaveLength(1);
  expect(vault.getEntry(id)?.item.login?.password).toBe("second");
  expect(JSON.parse(server.items[0]!.data).login.password).toBe("second");
  expect(vault.offlineSummary()).toBeNull();
});

test("ids from the popup must be UUIDs", async () => {
  await signedIn();
  await expectReject(vault.createItem(login("Example"), undefined, "../../admin"), (e) => e instanceof Error && e.message === "Not allowed.");
  expect(vault.validItemId(crypto.randomUUID())).toBe(true);
  expect(vault.validItemId("x")).toBe(false);
});

test("a stale revision is reported as revision_conflict and the vault is synced", async () => {
  await signedIn(["key_epoch"]);
  const id = await vault.createItem(login("Example"));
  const stale = vault.getEntry(id)!;
  server.editElsewhere(id, { notes: "elsewhere" });
  await expectReject(vault.updateItem(stale, { ...stale.item, notes: "here" }), (e) => e instanceof ApiError && e.code === "revision_conflict");
  // Synced: the next try starts from the other device's version.
  expect(vault.getEntry(id)?.item.notes).toBe("elsewhere");
});
