// Vault manifests in the service worker (background/vault.ts with background/manifests.ts), end to end against the
// fake server, which keeps manifests like the real one and checks every manifest a write brings with the real core
// (test/fake-server.ts, test/manifest-key.ts): verifying after every sync (full, delta, live, the offline copy at
// unlock), what is remembered, the warning and the writes held back, manifests on every write (create, edit, trash),
// the conflict loop, starting a manifest, deleting old trash, trash summaries and their hashes.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures, SERVER_UPDATE_TEXT } = await import("../src/background/api");
const { MANIFEST_BUSY_TEXT, MANIFEST_HELD_TEXT, MANIFEST_REVIEW_TEXT, MANIFEST_WARNING_TEXT, SERVED_HASH } = await import("../src/background/manifests");
const { dataHash } = await import("./manifest-key");

const FEATURES = ["key_epoch", "idempotent_create", "error_codes", "delta_sync", "vault_invitations", "policies", "vault_manifest"];
const V = "v-own";
const DAY = 86400;

let fake: FakeChrome;
let server: FakeServer;

const login = (name: string, notes = "") => ({
  name,
  notes,
  favorite: false,
  folder: null,
  tags: [],
  login: { username: "alex", password: `pw-${name}`, urls: [{ url: "https://example.com", match: "domain" as const }], totp: null, passkeys: [] },
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 0,
  updated_at: 0,
});

interface Setup {
  items?: number;
  /** The vault has a manifest already (version 1, by another device). Default: yes. */
  manifest?: boolean;
  features?: string[];
  /** Runs before the unlock (and the first sync). */
  before?: () => void;
}

/** Signed in, `items` logins on the server, the vault opened (first sync done). */
async function signedIn(setup: Setup = {}) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = setup.features ?? FEATURES;
  for (let n = 1; n <= (setup.items ?? 2); n++) server.addElsewhere(`i${n}`, V, JSON.stringify(login(`Item ${n}`)));
  if (setup.manifest !== false) server.startManifestElsewhere(V);
  setup.before?.();
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

/** Lock and open again from the offline copy, as after a browser restart (`online`: whether the server answers). */
async function reopen(online = true) {
  await vault.lockAll();
  vi.stubGlobal("fetch", online ? server.fetch : async () => Promise.reject(new TypeError("Failed to fetch")));
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

const row = () => server.vaults.find((v) => v.id === V)!;
const stored = () => storage.syncCache.get("a1");
const storedRow = async () => (await stored())?.vaults.find((v) => v.id === V) as unknown as { manifest?: string | null; manifest_seq?: number; seq?: number };
/** An item row of the offline copy, as stored ({} when it has none). */
const storedItem = async (id: string) => ((await stored())?.items.find((r) => r.id === id) ?? {}) as unknown as Record<string, unknown>;
const requestsSince = (n: number) => server.requests.slice(n).map((r) => `${r.method} ${r.path}`);
const syncs = () => server.requests.filter((r) => r.path === "/sync");
const sent = (method: string, path: string) => server.requests.filter((r) => r.method === method && r.path === path);
const ids = () =>
  vault
    .allEntries()
    .map((e) => e.id)
    .sort();
const warned = () => vault.manifestSummary()?.vaults.map((v) => v.id) ?? [];
/** A change on the server that the vault's manifest doesn't know of (what a dishonest server does): `fn`, served as a change. */
function tamper(fn: () => void) {
  fn();
  server.revision++;
  server.bump(V);
}
const serverItem = (id: string) => server.items.find((i) => i.id === id)!;

beforeEach(() => {
  vi.unstubAllGlobals();
});

test("a vault without a manifest: nothing new is sent or kept, and nothing is started while the server says some app is too old", async () => {
  await signedIn({ manifest: false });
  const id = await vault.createItem(login("New"));
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "changed" });
  await vault.trashItem(vault.getEntry(id)!);
  const writes = server.requests.filter((r) => r.method !== "GET");
  expect(writes.map((r) => `${r.method} ${r.path}`)).toStrictEqual(["POST /items", `PUT /items/${id}`, `DELETE /items/${id}`]);
  for (const w of writes) {
    expect(w.body && "manifests" in w.body, `${w.method} ${w.path}`).toBeFalsy();
    expect(w.query).toStrictEqual({});
  }
  expect((await stored())?.manifests).toBeUndefined();
  expect(vault.manifestSummary()).toBe(null);
  expect(row().manifest_seq ?? 0).toBe(0);
});

test("a server without the feature: no manifest fields, nothing checked, started or deleted", async () => {
  await signedIn({ manifest: false, features: FEATURES.filter((f) => f !== "vault_manifest"), before: () => (row().manifest_ok = true) });
  server.trashDays = 1;
  server.trashElsewhere("i1", 5);
  await vault.sync();
  expect(server.requests.filter((r) => r.method !== "GET")).toStrictEqual([]);
  expect(vault.manifestSummary()).toBe(null);
  expect(serverItem("i1")).toBeDefined();
});

test("every sync checks the vault against its manifest; the version seen is remembered with the offline copy and never lowered", async () => {
  await signedIn();
  expect((await stored())?.manifests).toStrictEqual({ [V]: 1 });
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 1 });
  expect(vault.manifestSummary()).toBe(null);
  // Changes by another device, each with the vault's next manifest: a delta, checked, remembered.
  server.editElsewhere("i1", { notes: "phone" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  server.trashElsewhere("i2");
  await vault.sync();
  expect(syncs().at(-1)?.query.since).toBeTruthy();
  expect(vault.manifestSummary()).toBe(null);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 4 });
  expect(ids()).toStrictEqual(["i1", "i3"]);
  // The trash summary carries the server's hash instead of the data, and keeps it in the offline copy.
  const trashed = await storedItem("i2");
  expect(trashed.data).toBeUndefined();
  expect(trashed.data_sha256).toBe(dataHash(serverItem("i2").data));
  // The offline copy is checked again at unlock, without the server: still in order.
  await reopen(false);
  expect(vault.manifestSummary()).toBe(null);
  expect(ids()).toStrictEqual(["i1", "i3"]);
  // A replaced vault key: the manifest was computed again for the new key and epoch, and opens with it.
  await reopen();
  server.rotate(V);
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 5 });
  expect(server.manifestErrors).toStrictEqual([]);
});

test("create, edit and trash carry the vault's next manifest; the write is shown without asking and its version remembered", async () => {
  await signedIn();
  let before = server.requests.length;
  const id = await vault.createItem(login("New"));
  expect(requestsSince(before), "no sync after the create").toStrictEqual(["POST /items"]);
  const post = sent("POST", "/items").at(-1)!;
  expect(post.body.manifests).toStrictEqual([{ vault_id: V, seq: 2, sealed: row().manifest }]);
  expect(post.headers["x-passauth-manifest"], "never in a header").toBeUndefined();
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 2 });
  expect((await stored())?.manifests).toStrictEqual({ [V]: 2 });

  before = server.requests.length;
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "changed" });
  expect(requestsSince(before)).toStrictEqual([`PUT /items/${id}`]);
  expect(sent("PUT", `/items/${id}`).at(-1)!.body.manifests).toStrictEqual([{ vault_id: V, seq: 3, sealed: row().manifest }]);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 3 });

  before = server.requests.length;
  const revision = serverItem(id).revision;
  await vault.trashItem(vault.getEntry(id)!);
  expect(requestsSince(before)).toStrictEqual([`DELETE /items/${id}`]);
  // No body: the manifest and the item's revision go in the query.
  expect(sent("DELETE", `/items/${id}`).at(-1)!.query).toStrictEqual({ revision: String(revision), manifest_seq: "4", manifest: row().manifest });
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 4 });
  expect((await stored())?.manifests).toStrictEqual({ [V]: 4 });
  expect(vault.getEntry(id)).toBeUndefined();
  // Every manifest sent described the vault after its write (the fake server checked each with the real core).
  expect(server.manifestErrors).toStrictEqual([]);

  // The trashed row keeps its data in the copy until the next delta, so the copy still matches its manifest offline…
  expect(typeof (await storedItem(id)).data).toBe("string");
  await reopen(false);
  expect(vault.manifestSummary()).toBe(null);
  // …and after the delta that brings the server's own row (a summary with its hash).
  await reopen();
  server.editElsewhere("i1", { notes: "again" });
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  const summary = await storedItem(id);
  expect([summary.data, summary.data_sha256]).toStrictEqual([undefined, dataHash(serverItem(id).data)]);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 5 });
});

test("an answer that doesn't name the manifest version sent (or none): not shown as sent; a sync follows and checks the vault", async () => {
  await signedIn();
  for (const patch of [{ manifest_seq: 99 }, { manifest_seq: undefined }]) {
    server.handlers["POST /items"] = (req) => {
      const r = server.route(req);
      return { ...r, body: { ...(r.body as object), ...patch } };
    };
    const before = server.requests.length;
    const id = await vault.createItem(login("New"));
    expect(requestsSince(before)).toStrictEqual(["POST /items", "GET /sync"]);
    expect(vault.getEntry(id)?.item.name).toBe("New");
    expect(vault.manifestSummary()).toBe(null);
  }
  expect((await stored())?.manifests).toStrictEqual({ [V]: 3 });
});

test("something else was written into the vault (409 manifest_conflict): sync, check, compute again, send again with the same id", async () => {
  await signedIn();
  // Create.
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  let before = server.requests.length;
  const id = await vault.createItem(login("New"));
  expect(requestsSince(before)).toStrictEqual(["POST /items", "GET /sync", "POST /items"]);
  const posts = sent("POST", "/items");
  expect(posts.map((r) => [r.body.id, r.body.manifests[0].seq])).toStrictEqual([
    [id, 2],
    [id, 3],
  ]);
  expect(ids()).toStrictEqual(["i1", "i2", "i3", id].sort());
  // Edit: another item changed elsewhere (not this one: that is a revision conflict).
  server.editElsewhere("i3", { notes: "elsewhere" });
  before = server.requests.length;
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "here" });
  expect(requestsSince(before)).toStrictEqual([`PUT /items/${id}`, "GET /sync", `PUT /items/${id}`]);
  expect(JSON.parse(serverItem(id).data).notes).toBe("here");
  expect(vault.getEntry("i3")?.item.notes).toBe("elsewhere");
  // Trash.
  server.editElsewhere("i3", { notes: "again" });
  before = server.requests.length;
  await vault.trashItem(vault.getEntry(id)!);
  expect(requestsSince(before)).toStrictEqual([`DELETE /items/${id}`, "GET /sync", `DELETE /items/${id}`]);
  expect(typeof serverItem(id).deleted_at).toBe("number");
  expect(server.manifestErrors).toStrictEqual([]);
  expect(vault.manifestSummary()).toBe(null);
  expect((await stored())?.manifests).toStrictEqual({ [V]: row().manifest_seq });
});

test("the conflict loop looks at the fresh copy first: an item trashed or gone elsewhere is done; an edited one is the usual conflict", async () => {
  await signedIn({ items: 4 });
  // Trash: already in the trash elsewhere → nothing is sent again.
  const one = vault.getEntry("i1")!;
  server.trashElsewhere("i1");
  let before = server.requests.length;
  await vault.trashItem(one);
  expect(requestsSince(before)).toStrictEqual(["DELETE /items/i1", "GET /sync"]);
  // Trash: the item itself was edited elsewhere (the server says so by its revision) → the fresh copy is trashed.
  const two = vault.getEntry("i2")!;
  server.editElsewhere("i2", { notes: "elsewhere" });
  before = server.requests.length;
  await vault.trashItem(two);
  expect(requestsSince(before)).toStrictEqual(["DELETE /items/i2", "GET /sync", "DELETE /items/i2"]);
  expect(typeof serverItem("i2").deleted_at).toBe("number");
  // Edit: the item was deleted elsewhere meanwhile → refused as changed elsewhere, nothing sent again.
  const three = vault.getEntry("i3")!;
  server.handlers["PUT /items/:id"] = () => {
    delete server.handlers["PUT /items/:id"];
    server.deleteElsewhere("i3");
    return { status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } };
  };
  before = server.requests.length;
  await expectReject(vault.updateItem(three, { ...three.item, notes: "here" }), (e) => e.code === "revision_conflict");
  expect(requestsSince(before)).toStrictEqual(["PUT /items/i3", "GET /sync"]);
  expect(vault.manifestSummary()).toBe(null);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("three refusals in a row: the write gives up with 'This vault changed on another device. Try again.'", async () => {
  await signedIn();
  const conflict = () => ({ status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } });
  server.handlers["POST /items"] = conflict;
  server.handlers["PUT /items/:id"] = conflict;
  server.handlers["DELETE /items/:id"] = conflict;
  const entry = vault.getEntry("i1")!;
  for (const [write, route] of [
    [() => vault.createItem(login("New")), "POST /items"],
    [() => vault.updateItem(entry, { ...entry.item, notes: "x" }), "PUT /items/i1"],
    [() => vault.trashItem(entry), "DELETE /items/i1"],
  ] as const) {
    const before = server.requests.length;
    await expectReject(write(), (e) => e.message === MANIFEST_BUSY_TEXT && e.code === "manifest_busy");
    expect(requestsSince(before), route).toStrictEqual([route, "GET /sync", route, "GET /sync", route]);
  }
  expect(server.items).toHaveLength(2);
});

test("400 manifest_required (the copy still said the vault has no manifest): handled like a conflict", async () => {
  await signedIn({ manifest: false });
  server.startManifestElsewhere(V);
  const before = server.requests.length;
  const id = await vault.createItem(login("New"));
  expect(requestsSince(before)).toStrictEqual(["POST /items", "GET /sync", "POST /items"]);
  expect(sent("POST", "/items").map((r) => r.body.manifests?.[0]?.seq)).toStrictEqual([undefined, 2]);
  expect(vault.getEntry(id)?.item.name).toBe("New");
  expect((await stored())?.manifests).toStrictEqual({ [V]: 2 });
  expect(server.manifestErrors).toStrictEqual([]);
});

test("a server that hides a change, brings an item back or serves other data: the vault stays readable, shows the warning, and takes no writes until it is resolved", async () => {
  const lies: Record<string, () => void> = {
    "hides an item": () => {
      server.items = server.items.filter((i) => i.id !== "i1");
      server.tombstones.push({ id: "i1", vault_id: V, seq: (row().seq ?? 0) + 1 });
    },
    "hides a new item's manifest (an item the record doesn't know)": () => {
      server.items.push({
        id: "i9",
        vault_id: V,
        item_key: `${row().wrapped_key}:i9`,
        data: JSON.stringify(login("Planted")),
        revision: server.revision + 1,
        deleted_at: null,
        seq: (row().seq ?? 0) + 1,
      });
    },
    "brings a trashed item back": () => {
      Object.assign(serverItem("i3"), { deleted_at: null, seq: (row().seq ?? 0) + 1, revision: server.revision + 1 });
    },
    "puts an item in the trash": () => {
      Object.assign(serverItem("i2"), { deleted_at: 5, seq: (row().seq ?? 0) + 1, revision: server.revision + 1 });
    },
    "serves other data for an item": () => {
      const i = serverItem("i2");
      Object.assign(i, { data: JSON.stringify({ ...JSON.parse(i.data), notes: "not what was written" }), seq: (row().seq ?? 0) + 1, revision: server.revision + 1 });
    },
    "serves a manifest that doesn't open": () => {
      row().manifest = `${row().manifest}x`;
    },
    "serves a manifest under a version it wasn't sealed for": () => {
      row().manifest_seq = (row().manifest_seq ?? 0) + 1;
    },
  };
  for (const [name, lie] of Object.entries(lies)) {
    await signedIn({ items: 3 });
    server.trashElsewhere("i3");
    await vault.sync();
    expect(warned(), name).toStrictEqual([]);
    const remembered = (await stored())?.manifests;
    expect(remembered).toStrictEqual({ [V]: 2 });
    tamper(lie);
    await vault.sync();
    const notice = vault.manifestSummary();
    expect(notice, name).toStrictEqual({ text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [{ id: V, name: "Personal" }], key: `["${V}"]` });
    expect(vault.manifestWarned(V), name).toBe(true);
    // Still readable (autofill still fills), with whatever the server sent.
    expect(vault.allEntries().length, name).toBeGreaterThan(0);
    // Nothing is remembered from an answer that doesn't match.
    expect((await stored())?.manifests, name).toStrictEqual(remembered);
    // Writes are refused here, before anything is sent.
    const before = server.requests.length;
    const entry = vault.allEntries()[0]!;
    for (const write of [() => vault.createItem(login("New")), () => vault.updateItem(entry, { ...entry.item, notes: "x" }), () => vault.trashItem(entry)]) {
      await expectReject(write(), (e) => e.message === MANIFEST_HELD_TEXT && e.code === "manifest_held");
    }
    expect(requestsSince(before), name).toStrictEqual([]);
    // The warning survives a restart without the server (the copy is checked again at unlock)…
    await reopen(false);
    expect(warned(), name).toStrictEqual([V]);
    // …and is gone by itself once an answer matches again: someone used "Use the server's copy" in the web vault.
    await reopen();
    server.revision++;
    server.bump(V);
    server.remanifest(V, 7);
    await vault.sync();
    expect(warned(), name).toStrictEqual([]);
    expect((await stored())?.manifests, name).toStrictEqual({ [V]: 7 });
    await vault.createItem(login("New"));
    expect(server.manifestErrors, name).toStrictEqual([]);
  }
});

test("rollback: an older manifest than the one seen (even with the items that went with it), or none at all, is never accepted; none is started in its place", async () => {
  await signedIn();
  const old = { items: structuredClone(server.items), manifest: row().manifest, manifest_seq: row().manifest_seq };
  server.editElsewhere("i1", { notes: "new password" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  await vault.sync();
  expect((await stored())?.manifests).toStrictEqual({ [V]: 3 });
  // The whole vault as it was at version 1: consistent in itself, but older than what this browser saw.
  tamper(() => {
    server.items = old.items.map((i) => ({ ...i, seq: (row().seq ?? 0) + 1 }));
    server.tombstones.push({ id: "i3", vault_id: V, seq: (row().seq ?? 0) + 1 });
    Object.assign(row(), { manifest: old.manifest, manifest_seq: old.manifest_seq });
  });
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect((await stored())?.manifests, "never lowered").toStrictEqual({ [V]: 3 });
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
  // No manifest any more, with the server saying a first one may be started: still a rollback, and none is started.
  tamper(() => Object.assign(row(), { manifest: null, manifest_seq: 0, manifest_ok: true }));
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 3 });
  // A server that stops listing the feature (and sends no manifest fields) doesn't switch the check off either.
  server.features = FEATURES.filter((f) => f !== "vault_manifest");
  forgetServerFeatures();
  server.revision++;
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  await reopen(false);
  expect(warned()).toStrictEqual([V]);
});

test("an offline copy from before the server sent trash hashes (incomplete): no warning; everything is fetched once and checked", async () => {
  await signedIn();
  server.trashElsewhere("i1");
  await vault.sync();
  /** The copy as an earlier version stored it: the trash summary without `data_sha256`. */
  const strip = async () => {
    await vault.lockAll();
    const copy = (await stored())!;
    for (const r of copy.items as unknown as Record<string, unknown>[]) delete r.data_sha256;
    await storage.syncCache.set("a1", copy);
  };
  await strip();
  let before = syncs().length;
  await reopen();
  expect(warned(), "not a mismatch").toStrictEqual([]);
  // Writes wait for the fetch instead of failing.
  const id = await vault.createItem(login("New"));
  expect(vault.getEntry(id)?.item.name).toBe("New");
  await vault.sync();
  // A delta first (nothing new: still incomplete), then the whole vault, once.
  const queries = syncs()
    .slice(before)
    .map((r) => Object.keys(r.query).sort().join("+"));
  expect(queries.slice(0, 2)).toStrictEqual(["since+trash", "trash"]);
  expect(queries.filter((q) => q === "trash")).toHaveLength(1);
  expect(warned()).toStrictEqual([]);
  expect((await storedItem("i1")).data_sha256).toBe(dataHash(serverItem("i1").data));
  expect(server.manifestErrors).toStrictEqual([]);

  // A server that still sends no hashes after the full fetch: a mismatch, never "incomplete" for good.
  await strip();
  server.omitHashes = true;
  before = syncs().length;
  await reopen();
  await vault.sync();
  expect(
    syncs()
      .slice(before)
      .filter((r) => !r.query.since).length,
  ).toBeGreaterThanOrEqual(1);
  expect(warned()).toStrictEqual([V]);
  await expectReject(vault.createItem(login("Again")), (e) => e.message === MANIFEST_HELD_TEXT);
});

test("starting a vault's first manifest: once the server says every member's app can, from the rows of that sync, shown without asking", async () => {
  await signedIn({ manifest: false, before: () => (row().manifest_ok = true) });
  const puts = () => sent("PUT", `/vaults/${V}/manifest`);
  expect(puts()).toHaveLength(1);
  expect(puts()[0]!.body).toStrictEqual({ base_seq: 0, seq: 1, sealed: row().manifest, vault_seq: 2 });
  expect(server.manifestErrors).toStrictEqual([]);
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 1 });
  expect((await stored())?.own).toStrictEqual({ [V]: 3 });
  expect((await stored())?.manifests).toStrictEqual({ [V]: 1 });
  expect(syncs(), "no sync after it").toHaveLength(1);
  // The next write carries version 2 and is shown without asking.
  const before = server.requests.length;
  await vault.createItem(login("New"));
  expect(requestsSince(before)).toStrictEqual(["POST /items"]);
  expect(sent("POST", "/items")[0]!.body.manifests[0].seq).toBe(2);
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect(puts()).toHaveLength(1);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("starting a manifest: not while the gate is closed, not with read access; one try per vault state, failures ignored", async () => {
  // The gate is closed.
  await signedIn({ manifest: false });
  await vault.sync();
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
  // Read access.
  await signedIn({ manifest: false, before: () => Object.assign(row(), { manifest_ok: true, role: "read" }) });
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
  // The server refuses (some app signed in meanwhile is too old): ignored, not tried again for the same vault state…
  await signedIn({
    manifest: false,
    before: () => {
      row().manifest_ok = true;
      server.handlers[`PUT /vaults/${V}/manifest`] = () => ({ status: 409, body: { error: "manifest_not_ready", message: "some apps are too old" } });
    },
  });
  const puts = () => sent("PUT", `/vaults/${V}/manifest`).length;
  expect(puts()).toBe(1);
  expect(vault.manifestSummary()).toBe(null);
  server.revision++;
  await vault.sync();
  expect(puts()).toBe(1);
  // …but again after the vault changed, and then it works. Writes meanwhile went without a manifest, as before.
  const id = await vault.createItem(login("New"));
  expect(sent("POST", "/items")[0]!.body.manifests).toBeUndefined();
  delete server.handlers[`PUT /vaults/${V}/manifest`];
  server.editElsewhere(id, { notes: "elsewhere" });
  await vault.sync();
  expect(puts()).toBe(2);
  expect(row().manifest_seq).toBe(1);
  expect(server.manifestErrors).toStrictEqual([]);
  expect((await stored())?.manifests).toStrictEqual({ [V]: 1 });
});

test("old trash: after a sync, trashed items past the server's trash setting (by the server's clock) are deleted for good with the vault's next manifest", async () => {
  const now = 1_800_000_000;
  await signedIn({ items: 4 });
  server.now = now;
  server.trashDays = 30;
  server.trashElsewhere("i1", now - 31 * DAY);
  server.trashElsewhere("i2", now - 29 * DAY);
  server.trashElsewhere("i3", now - 400 * DAY);
  const before = server.requests.length;
  await vault.sync();
  expect(requestsSince(before)).toStrictEqual(["GET /sync", `POST /vaults/${V}/trash/purge`]);
  const purge = sent("POST", `/vaults/${V}/trash/purge`)[0]!;
  expect(purge.body.items).toStrictEqual([
    { id: "i1", revision: expect.any(Number) },
    { id: "i3", revision: expect.any(Number) },
  ]);
  expect(purge.body.manifests).toStrictEqual([{ vault_id: V, seq: 5, sealed: row().manifest }]);
  expect(server.manifestErrors).toStrictEqual([]);
  expect(server.items.map((i) => i.id).sort()).toStrictEqual(["i2", "i4"]);
  // Shown without asking: the rows are gone from the copy, the manifest and its version kept.
  expect((await stored())?.items.map((r) => r.id).sort()).toStrictEqual(["i2", "i4"]);
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 5 });
  expect((await stored())?.manifests).toStrictEqual({ [V]: 5 });
  // The next delta (it lists them as deleted) matches.
  server.editElsewhere("i4", { notes: "x" });
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect(sent("POST", `/vaults/${V}/trash/purge`)).toHaveLength(1);
});

test("old trash: nothing with trash kept forever or read access; one request of at most the server's batch size per sync; a failure is ignored and not repeated", async () => {
  const now = 1_800_000_000;
  const purges = () => sent("POST", `/vaults/${V}/trash/purge`);
  const old = () => {
    server.now = now;
    for (const id of ["i1", "i2", "i3"]) server.trashElsewhere(id, now - 90 * DAY);
  };
  // Kept forever.
  await signedIn({ items: 3, before: old });
  expect(purges()).toHaveLength(0);
  // Read access.
  await signedIn({
    items: 3,
    before: () => {
      old();
      server.trashDays = 30;
      row().role = "read";
    },
  });
  expect(purges()).toHaveLength(0);
  // The admin's batch limit: one request per sync, the rest at the next one.
  await signedIn({
    items: 3,
    before: () => {
      old();
      server.trashDays = 30;
      server.limits = { max_import_items: 2 };
    },
  });
  expect(purges().map((r) => r.body.items.length)).toStrictEqual([2]);
  server.revision++;
  await vault.sync();
  expect(purges().map((r) => r.body.items.length)).toStrictEqual([2, 1]);
  expect(server.items).toStrictEqual([]);
  expect(server.manifestErrors).toStrictEqual([]);
  // Refused (another device was faster, say): ignored, the sync still succeeds, and the same state isn't tried twice.
  await signedIn({
    items: 3,
    before: () => {
      old();
      server.trashDays = 30;
      server.handlers[`POST /vaults/${V}/trash/purge`] = () => ({ status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } });
    },
  });
  expect(purges()).toHaveLength(1);
  server.revision++;
  await vault.sync();
  expect(purges()).toHaveLength(1);
  expect(vault.manifestSummary()).toBe(null);
  expect(server.items).toHaveLength(3);
});

test("a newer copy this browser kept instead of an older version the server sent counts by what the server sent: no false mismatch, and its edit still carries a right manifest", async () => {
  await signedIn();
  const old = { ...serverItem("i1") };
  const entry = vault.getEntry("i1")!;
  await vault.updateItem(entry, { ...entry.item, notes: "the newer one" });
  // The server serves the older version again, with a manifest that says so (a new baseline made elsewhere).
  Object.assign(serverItem("i1"), { item_key: old.item_key, data: old.data, revision: ++server.revision, seq: server.bump(V) });
  server.remanifest(V);
  await vault.sync();
  expect(vault.rolledBack("i1")).toBe(true);
  expect(vault.getEntry("i1")?.item.notes, "the newer copy is kept and shown").toBe("the newer one");
  expect(vault.manifestSummary(), "the manifest is about the server's rows").toBe(null);
  const kept = await storedItem("i1");
  expect(kept[SERVED_HASH]).toBe(dataHash(old.data));
  // Still in order after a restart from the copy, and the kept item can be saved again (the server's row goes).
  await reopen();
  expect(vault.manifestSummary()).toBe(null);
  const again = vault.getEntry("i1")!;
  const before = server.requests.length;
  await vault.updateItem(again, { ...again.item, notes: "saved again" });
  expect(requestsSince(before).filter((r) => r.startsWith("PUT"))).toStrictEqual(["PUT /items/i1"]);
  expect(server.manifestErrors).toStrictEqual([]);
  expect(JSON.parse(serverItem("i1").data).notes).toBe("saved again");
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
});

test("live sync and the revision check verify too: a change announced over the socket that doesn't match raises the warning", async () => {
  await signedIn();
  tamper(() => {
    server.items = server.items.filter((i) => i.id !== "i1");
    server.tombstones.push({ id: "i1", vault_id: V, seq: (row().seq ?? 0) + 1 });
  });
  await vault.liveNotice({ type: "sync", revision: server.revision, vaults: { [V]: row().seq } });
  expect(warned()).toStrictEqual([V]);
  server.revision++;
  server.bump(V);
  server.remanifest(V);
  await vault.refreshIfStale();
  expect(warned()).toStrictEqual([]);
});

test("the popup: the warning names the vault and points to the web vault or the desktop app (no 'Use the server's copy' here); a refused server says so", async () => {
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { createElement } = await import("react");
  const { Notices } = await import("../src/popup/notices");
  const ctx = { signIns: null, state: { server: "https://vault.test" }, go: () => {}, notify: () => {} } as never;
  const manifest = { text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [{ id: V, name: "Personal" }], key: "k" };
  const html = renderToStaticMarkup(createElement(Notices, { ctx, data: { manifest } as never, tabId: undefined }));
  expect(html).toContain("Personal");
  expect(html).toContain("Your server&#x27;s copy of this vault doesn&#x27;t match its record of changes. Items may be missing, restored or out of date.");
  expect(html).toContain("Open the web vault or the desktop app to review this vault.");
  expect(html).not.toContain("Use the server");
  expect(html, "it can't be dismissed").not.toContain("Dismiss");
  const outdated = renderToStaticMarkup(createElement(Notices, { ctx, data: { serverProblem: SERVER_UPDATE_TEXT } as never, tabId: undefined }));
  expect(outdated).toContain("Update your PassAuth server to keep using this app.");
  expect(renderToStaticMarkup(createElement(Notices, { ctx, data: {} as never, tabId: undefined }))).toBe("");
});
