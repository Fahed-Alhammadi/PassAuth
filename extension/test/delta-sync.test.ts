// Delta sync in the service worker (background/vault.ts with @web/lib/delta): the offline copy keeps the cursor and
// vault numbers with its rows, syncs ask only for what changed (trash=summary) and decrypt only that, own writes are
// shown without asking when their vault number is the next one, live-sync messages and /sync/revision decide by the
// vault numbers, and older servers keep the old behaviour.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { deferred } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const { FakeAccount, FakeVaultKey } = await import("./fake-core");
const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures, setTwoStepHandler } = await import("../src/background/api");
const { noteTwoStepRequired } = await import("../src/background/policies");

const DELTA = ["key_epoch", "idempotent_create", "error_codes", "delta_sync", "vault_invitations", "policies"];

let fake: FakeChrome;
let server: FakeServer;

const login = (name: string, notes = "") =>
  JSON.stringify({
    name,
    notes,
    favorite: false,
    folder: null,
    tags: [],
    login: { username: "alex", password: `pw-${name}`, urls: [{ url: "https://example.com", match: "domain" }], totp: null, passkeys: [] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: 0,
    updated_at: 0,
  });

/** Signed in with `items` logins on the server, the vault opened (first sync done). */
async function signedIn(features = DELTA, items = 2) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = features;
  for (let n = 1; n <= items; n++) server.addElsewhere(`i${n}`, "v-own", login(`Item ${n}`));
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

const syncs = () => server.requests.filter((r) => r.path === "/sync");
const stored = () => storage.syncCache.get("a1");
const ids = () =>
  vault
    .allEntries()
    .map((e) => e.id)
    .sort();
const requestsSince = (n: number) => server.requests.slice(n).map((r) => `${r.method} ${r.path}`);

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("first sync: the whole vault with trash=summary; the offline copy keeps the cursor and vault numbers with its rows", async () => {
  await signedIn();
  expect(syncs().map((r) => r.query)).toStrictEqual([{ trash: "summary" }]);
  const copy = await stored();
  expect(copy?.cursor).toBe(server.cursor());
  expect(copy?.vaults.map((v) => v.seq)).toStrictEqual([2]);
  expect(copy?.items.map((r) => r.id).sort()).toStrictEqual(["i1", "i2"]);
  expect(ids()).toStrictEqual(["i1", "i2"]);
});

test("a later sync asks only for what changed since the cursor, and decrypts only that", async () => {
  await signedIn();
  const cursor = (await stored())?.cursor;
  const untouched = vault.getEntry("i2");
  server.editElsewhere("i1", { notes: "from the phone" });
  const decrypt = vi.spyOn(FakeVaultKey.prototype, "decryptItem");
  await vault.sync();
  expect(syncs().at(-1)?.query).toStrictEqual({ since: cursor, trash: "summary" });
  expect(decrypt, "only the changed item").toHaveBeenCalledTimes(1);
  expect(vault.getEntry("i1")?.item.notes).toBe("from the phone");
  expect(vault.getEntry("i2"), "an unchanged item keeps its decrypted copy").toBe(untouched);
  expect((await stored())?.cursor).toBe(server.cursor());
});

test("deleted elsewhere, a replaced vault key, a vault gone: removed, re-opened and dropped", async () => {
  await signedIn(DELTA, 3);
  server.deleteElsewhere("i2");
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i3"]);

  // A key replacement resets the vault: its key is opened again and every item decrypted under it.
  const open = vi.spyOn(FakeAccount.prototype, "openVaultKey");
  server.rotate("v-own");
  await vault.sync();
  // Once for the signed-sharing check of the row, once to use the vault.
  expect(open).toHaveBeenCalledTimes(2);
  expect(syncs().at(-1)?.query.since).toBeTruthy();
  expect(ids()).toStrictEqual(["i1", "i3"]);
  expect(vault.getEntry("i1")?.item.name).toBe("Item 1");

  // A shared vault arrives whole, then goes (left, or removed): its items go with it.
  server.vaults.push({ id: "v-team", wrapped_key: "team-1", key_kind: "sealed", role: "write", meta: JSON.stringify({ name: "Team" }), key_epoch: 1 });
  server.addElsewhere("t1", "v-team", login("Team login"));
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i3", "t1"]);
  server.vaults = server.vaults.filter((v) => v.id !== "v-team");
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i3"]);
  expect((await stored())?.items.some((r) => r.id === "t1")).toBe(false);
});

test("own writes: the vault's next number is shown as sent without asking; anything else is a delta sync", async () => {
  await signedIn();
  const cursor = (await stored())?.cursor;
  let before = server.requests.length;
  const id = await vault.createItem(JSON.parse(login("New one")));
  expect(requestsSince(before), "no sync after the create").toStrictEqual(["POST /items"]);
  expect(vault.getEntry(id)?.item.name).toBe("New one");
  // Kept in the offline copy, the cursor behind it (the next delta sends the row again).
  const copy = await stored();
  expect(copy?.items.some((r) => r.id === id)).toBe(true);
  expect(copy?.cursor).toBe(cursor);
  expect(copy?.own).toStrictEqual({ "v-own": 3 });

  // Another device wrote in between: the answer's number skips one, so a delta sync follows.
  server.editElsewhere("i1", { notes: "elsewhere" });
  before = server.requests.length;
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "here" });
  expect(requestsSince(before)).toStrictEqual([`PUT /items/${id}`, "GET /sync"]);
  expect(syncs().at(-1)?.query.since).toBe(cursor);
  expect(vault.getEntry("i1")?.item.notes).toBe("elsewhere");
  expect(vault.getEntry(id)?.item.notes).toBe("here");

  // Moving to the trash (which the extension never shows): gone at once, no sync.
  before = server.requests.length;
  await vault.trashItem(vault.getEntry(id)!);
  expect(requestsSince(before)).toStrictEqual([`DELETE /items/${id}`]);
  expect(vault.getEntry(id)).toBeUndefined();
  // The next delta brings the server's own row for it: a trash summary, still not shown.
  server.editElsewhere("i1", { notes: "again" });
  await vault.sync();
  expect(vault.getEntry(id)).toBeUndefined();
  const trashed = (await stored())?.items.find((r) => r.id === id);
  expect(typeof trashed?.deleted_at).toBe("number");
  expect(trashed && ("data" in trashed || "item_key" in trashed)).toBe(false);
});

test("an older server (no delta_sync): the whole vault every time, without since or trash=summary, and a sync after every write", async () => {
  await signedIn(["key_epoch", "idempotent_create", "error_codes"]);
  await vault.sync();
  expect(syncs().map((r) => r.query)).toStrictEqual([{}, {}]);
  const before = server.requests.length;
  await vault.createItem(JSON.parse(login("New one")));
  expect(requestsSince(before)).toStrictEqual(["POST /items", "GET /sync"]);
  expect((await stored())?.cursor).toBeUndefined();
});

test("a delta this browser can't use: the whole vault, once", async () => {
  await signedIn();
  server.handlers["GET /sync"] = (req) => (req.query.since ? { body: { ...server.syncAnswer(req.query), deleted: "not a list" } } : undefined);
  server.editElsewhere("i1", { notes: "x" });
  await vault.sync();
  expect(
    syncs()
      .slice(-2)
      .map((r) => Object.keys(r.query).sort()),
  ).toStrictEqual([["since", "trash"], ["trash"]]);
  expect(vault.getEntry("i1")?.item.notes).toBe("x");
});

test("an answer that arrives after a lock is dropped: the previous offline copy stays whole", async () => {
  await signedIn();
  const before = await stored();
  const held = deferred();
  const fetchServer = server.fetch;
  vi.stubGlobal("fetch", async (input: string, init?: RequestInit) => {
    if (String(input).includes("/sync?since")) await held.promise;
    return fetchServer(input, init);
  });
  server.editElsewhere("i1", { notes: "late" });
  const running = vault.sync();
  await new Promise((r) => setTimeout(r, 10));
  await vault.lockAll();
  held.resolve();
  await running;
  expect(await stored()).toStrictEqual(before);
});

test("after a worker restart: the copy's vault numbers are checked with /sync/revision; nothing new → no sync, a change → a delta", async () => {
  await signedIn();
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  const before = syncs().length;
  expect(await vault.ensureUnlocked()).toBe(true);
  await vault.refreshIfStale();
  expect(syncs().length, "opened from the copy, nothing to fetch").toBe(before);
  server.editElsewhere("i2", { notes: "new" });
  await vault.refreshIfStale();
  expect(syncs().length).toBe(before + 1);
  expect(syncs().at(-1)?.query.since).toBeTruthy();
  expect(vault.getEntry("i2")?.item.notes).toBe("new");
});

test("live-sync messages: numbers the copy has (own writes too) are skipped, newer or unknown ones and {} sync; the origin never decides", async () => {
  await signedIn();
  const count = () => syncs().length;
  let n = count();
  await vault.liveNotice({ type: "sync", revision: server.revision, vaults: { "v-own": 2 } });
  expect(count()).toBe(n);
  // An own write shown without asking: its message (a newer revision, the number the copy has) is skipped too.
  await vault.createItem(JSON.parse(login("Mine")));
  n = count();
  await vault.liveNotice({ type: "sync", revision: server.revision, vaults: { "v-own": 3 }, origin: "someone-else" });
  expect(count()).toBe(n);
  // Another device: a newer number, even with this session's origin.
  server.editElsewhere("i1", { notes: "phone" });
  await vault.liveNotice({ type: "sync", revision: server.revision, vaults: { "v-own": 4 }, origin: "this-session" });
  expect(count()).toBe(n + 1);
  expect(vault.getEntry("i1")?.item.notes).toBe("phone");
  // A vault the copy doesn't know (shared with the account), and a profile change ({}), sync when newer.
  await vault.liveNotice({ type: "sync", revision: server.revision + 1, vaults: { "v-new": 1 } });
  expect(count()).toBe(n + 2);
  await vault.liveNotice({ type: "sync", revision: server.revision + 1, vaults: {} });
  expect(count()).toBe(n + 3);
  // Nothing newer than the last answer: skipped whatever the numbers.
  await vault.liveNotice({ type: "sync", revision: 1, vaults: {} });
  expect(count()).toBe(n + 3);
});

test("the live-sync check: older server → unsupported, no tokens → signed out, 403 two_step_required → two_step (and the popup says so)", async () => {
  await signedIn(["key_epoch"]);
  expect(await vault.checkForChanges()).toBe("unsupported");

  await signedIn();
  setTwoStepHandler(noteTwoStepRequired);
  server.editElsewhere("i1", { notes: "changed" });
  expect(await vault.checkForChanges()).toBe("ok");
  expect(vault.getEntry("i1")?.item.notes, "a stale copy is synced").toBe("changed");

  server.handlers["GET /sync/revision"] = () => ({ status: 403, body: { error: "two_step_required", message: "this server requires two-step login" } });
  expect(await vault.checkForChanges()).toBe("two_step");
  expect((await vault.state()).twoStepRequired).toBe(true);
  delete server.handlers["GET /sync/revision"];
  await vault.refreshIfStale();
  expect((await vault.state()).twoStepRequired).toBeUndefined();

  await fake.local.set({ accounts: { a1: { ...accountRecord(), tokens: null } } });
  expect(await vault.checkForChanges()).toBe("signed_out");
});

test("invitations: counted from every answer, for the popup's notice", async () => {
  await signedIn();
  expect(vault.invitations()).toStrictEqual({ count: 0, key: "" });
  server.invitations = [
    { vault_id: "v9", role: "write", wrapped_key: "sealed", meta: "name", invited_by: null, invited_at: 1 },
    { vault_id: "v8", role: "read", wrapped_key: "sealed", meta: "name", invited_by: null, invited_at: 2 },
  ];
  server.revision++;
  await vault.sync();
  expect(vault.invitations()).toStrictEqual({ count: 2, key: "v8,v9" });
});
