// Vault manifests in the service worker (background/vault.ts with background/manifests.ts), end to end against the
// fake server, which keeps manifests like the real one and checks every manifest a write brings with the real core
// (test/fake-server.ts, test/manifest-key.ts): verifying after every sync (full, delta, live, the offline copy at
// unlock), what is remembered, the warning and the writes held back, manifests on every write (create, edit, trash),
// the conflict loop, starting a manifest, deleting old trash, trash summaries and their hashes.
//
// And the review fixes: the chain (every manifest names the one it replaces; "fork then join" is refused, with and
// without the log; an answer whose log can't be fetched is not used), a row field a server sends is never taken for
// this browser's own marker, a hidden item is a mismatch, no warning from bookkeeping (a delta or the offline copy
// gets one full fetch first), an answer behind an own write is asked for again, old trash only after this browser
// watched it for the period, and what is remembered outliving the offline copy.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures, SERVER_UPDATE_TEXT, UNREACHABLE_TEXT } = await import("../src/background/api");
const { MANIFEST_BUSY_TEXT, MANIFEST_HELD_TEXT, MANIFEST_REVIEW_TEXT, MANIFEST_WARNING_TEXT, SERVED_HASH } = await import("../src/background/manifests");
const { dataHash, manifestLink, ZERO_LINK } = await import("./manifest-key");

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
const storedRow = async () => (await stored())?.vaults.find((v) => v.id === V) as unknown as { manifest?: string | null; manifest_seq?: number; manifest_prev?: string | null; seq?: number };
/** What this browser remembers (its device memory record, not the offline copy): per vault `{version, link}`. */
const memory = async () =>
  ((await storage.deviceMemory.read("https://vault.test", "u-1")) ?? {}) as {
    manifests?: Record<string, { version: number; link: string }>;
    trashSeen?: Record<string, number>;
    itemRevs?: Record<string, number>;
  };
/** The versions remembered per vault (undefined: none). */
const versions = async () => {
  const m = (await memory()).manifests;
  return m ? Object.fromEntries(Object.entries(m).map(([id, r]) => [id, r.version])) : undefined;
};
/** The link of the server's current manifest of the vault. */
const link = () => server.linkOf(V);
/** This browser's clock (Unix seconds), for the tests that move it. */
let clock: number | null = null;
const at = (seconds: number) => {
  clock = seconds;
};
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
  vi.restoreAllMocks();
  clock = null;
  const real = Date.now.bind(Date);
  vi.spyOn(Date, "now").mockImplementation(() => (clock === null ? real() : clock * 1000));
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
  expect(await versions()).toBeUndefined();
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
  expect(await versions()).toStrictEqual({ [V]: 1 });
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 1, manifest_prev: ZERO_LINK });
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link() } });
  expect((await stored()) as unknown as Record<string, unknown>, "the memory is not part of the offline copy").not.toHaveProperty("manifests");
  expect(vault.manifestSummary()).toBe(null);
  // Changes by another device, each with the vault's next manifest: a delta, checked, remembered.
  server.editElsewhere("i1", { notes: "phone" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  server.trashElsewhere("i2");
  await vault.sync();
  expect(syncs().at(-1)?.query.since).toBeTruthy();
  expect(vault.manifestSummary()).toBe(null);
  // Three steps ahead of the remembered manifest: the vault's log connects them (one request).
  expect(sent("GET", `/vaults/${V}/manifest-log`).map((r) => r.query)).toStrictEqual([{ after: "1" }]);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 4, link: link() } });
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
  expect(await versions()).toStrictEqual({ [V]: 5 });
  expect(server.manifestErrors).toStrictEqual([]);
});

test("create, edit and trash carry the vault's next manifest; the write is shown without asking and its version remembered", async () => {
  await signedIn();
  let before = server.requests.length;
  const first = link();
  const id = await vault.createItem(login("New"));
  expect(requestsSince(before), "no sync after the create").toStrictEqual(["POST /items"]);
  const post = sent("POST", "/items").at(-1)!;
  expect(post.body.manifests).toStrictEqual([{ vault_id: V, seq: 2, prev: first, sealed: row().manifest }]);
  expect(post.headers["x-passauth-manifest"], "never in a header").toBeUndefined();
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 2, manifest_prev: first });
  // The version and the link of the manifest this browser wrote are remembered with the copy that carries it.
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 2, link: link() } });
  const second = link();

  before = server.requests.length;
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "changed" });
  expect(requestsSince(before)).toStrictEqual([`PUT /items/${id}`]);
  expect(sent("PUT", `/items/${id}`).at(-1)!.body.manifests).toStrictEqual([{ vault_id: V, seq: 3, prev: second, sealed: row().manifest }]);
  const third = link();
  expect(await versions()).toStrictEqual({ [V]: 3 });

  before = server.requests.length;
  const revision = serverItem(id).revision;
  await vault.trashItem(vault.getEntry(id)!);
  expect(requestsSince(before)).toStrictEqual([`DELETE /items/${id}`]);
  // No body: the manifest and the item's revision go in the query.
  expect(sent("DELETE", `/items/${id}`).at(-1)!.query).toStrictEqual({ revision: String(revision), manifest_seq: "4", manifest_prev: third, manifest: row().manifest });
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 4, manifest_prev: third });
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 4, link: link() } });
  // Own writes one after another never need the log.
  expect(sent("GET", `/vaults/${V}/manifest-log`)).toStrictEqual([]);
  expect(await versions()).toStrictEqual({ [V]: 4 });
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
  expect(await versions()).toStrictEqual({ [V]: 5 });
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
  expect(await versions()).toStrictEqual({ [V]: 3 });
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
  expect(await versions()).toStrictEqual({ [V]: row().manifest_seq });
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
  expect(await versions()).toStrictEqual({ [V]: 2 });
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
    const remembered = await versions();
    expect(remembered).toStrictEqual({ [V]: 2 });
    const honest = { manifest: row().manifest, manifest_seq: row().manifest_seq, manifest_prev: row().manifest_prev };
    const asked = syncs().length;
    tamper(lie);
    await vault.sync();
    // No warning comes from a delta merged into this browser's own copy: the whole vault is fetched once, and that
    // answer decides.
    expect(
      syncs()
        .slice(asked)
        .map((r) => Object.keys(r.query).sort().join("+")),
      name,
    ).toStrictEqual(["since+trash", "trash"]);
    const notice = vault.manifestSummary();
    expect(notice, name).toStrictEqual({ text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [{ id: V, name: "Personal" }], key: `["${V}"]` });
    expect(vault.manifestWarned(V), name).toBe(true);
    // Still readable (autofill still fills), with whatever the server sent.
    expect(vault.allEntries().length, name).toBeGreaterThan(0);
    // Nothing is remembered from an answer that doesn't match.
    expect(await versions(), name).toStrictEqual(remembered);
    // Writes are refused here, before anything is sent.
    const before = server.requests.length;
    const entry = vault.allEntries()[0]!;
    for (const write of [() => vault.createItem(login("New")), () => vault.updateItem(entry, { ...entry.item, notes: "x" }), () => vault.trashItem(entry)]) {
      await expectReject(write(), (e) => e.message === MANIFEST_HELD_TEXT && e.code === "manifest_held");
    }
    expect(requestsSince(before), name).toStrictEqual([]);
    // After a restart without the server the copy is this browser's bookkeeping, not an answer: no warning is raised
    // from it, and nothing is written until a sync has decided (which fails: the server can't be reached).
    await reopen(false);
    expect(warned(), name).toStrictEqual([]);
    await expectReject(vault.createItem(login("New")), (e) => e.message === UNREACHABLE_TEXT);
    // With the server back the whole vault is fetched, and the warning is there again…
    await reopen();
    await vault.sync();
    expect(warned(), name).toStrictEqual([V]);
    // …and is gone by itself once an answer matches again: the server shows the record it had (where it lied about
    // the record itself), and someone used "Use the server's copy" in the web vault (a new baseline on that record).
    Object.assign(row(), honest);
    server.revision++;
    server.bump(V);
    server.remanifest(V, 7);
    await vault.sync();
    expect(warned(), name).toStrictEqual([]);
    expect(await versions(), name).toStrictEqual({ [V]: 7 });
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
  expect(await versions()).toStrictEqual({ [V]: 3 });
  // The whole vault as it was at version 1: consistent in itself, but older than what this browser saw.
  tamper(() => {
    server.items = old.items.map((i) => ({ ...i, seq: (row().seq ?? 0) + 1 }));
    server.tombstones.push({ id: "i3", vault_id: V, seq: (row().seq ?? 0) + 1 });
    Object.assign(row(), { manifest: old.manifest, manifest_seq: old.manifest_seq });
  });
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(await versions(), "never lowered").toStrictEqual({ [V]: 3 });
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
  // No manifest any more, with the server saying a first one may be started: still a rollback, and none is started.
  tamper(() => Object.assign(row(), { manifest: null, manifest_seq: 0, manifest_ok: true }));
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
  expect(await versions()).toStrictEqual({ [V]: 3 });
  // A server that stops listing the feature (and sends no manifest fields) doesn't switch the check off either.
  server.features = FEATURES.filter((f) => f !== "vault_manifest");
  forgetServerFeatures();
  server.revision++;
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // (After a restart the warning comes back with the first answer, not from the copy.)
  await reopen(false);
  expect(warned()).toStrictEqual([]);
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(await versions()).toStrictEqual({ [V]: 3 });
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
  // The copy can't be checked as it is: the whole vault is fetched, once.
  const queries = syncs()
    .slice(before)
    .map((r) => Object.keys(r.query).sort().join("+"));
  expect(queries[0]).toBe("trash");
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
  expect(puts()[0]!.body).toStrictEqual({ base_seq: 0, seq: 1, prev: ZERO_LINK, sealed: row().manifest, vault_seq: 2 });
  expect(server.manifestErrors).toStrictEqual([]);
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 1, manifest_prev: ZERO_LINK });
  expect((await stored())?.own).toStrictEqual({ [V]: 3 });
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: manifestLink(1, ZERO_LINK, row().manifest!) } });
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
  expect(await versions()).toStrictEqual({ [V]: 1 });
});

test("old trash: deleted for good with the vault's next manifest, but only once this browser has itself seen the items in the trash for the whole period", async () => {
  const now = 1_800_000_000;
  at(now);
  await signedIn({ items: 4 });
  server.now = now;
  server.trashDays = 30;
  server.trashElsewhere("i1", now - 31 * DAY);
  server.trashElsewhere("i2", now - 29 * DAY);
  server.trashElsewhere("i3", now - 400 * DAY);
  let before = server.requests.length;
  await vault.sync();
  // The server's rule says i1 and i3 are due. This browser sees them in the trash for the first time: nothing goes.
  expect(requestsSince(before)).toStrictEqual(["GET /sync", `GET /vaults/${V}/manifest-log`]);
  expect((await memory()).trashSeen).toStrictEqual({ i1: now, i2: now, i3: now });
  const purges = () => sent("POST", `/vaults/${V}/trash/purge`);
  // 29 days later: still not the whole period by this browser's own clock.
  at(now + 29 * DAY);
  server.now = now + 29 * DAY;
  server.revision++;
  await vault.sync();
  expect(purges()).toHaveLength(0);
  // 30 days after it first saw them: now they go (i2 too: it has been in the trash for 59 days by then).
  at(now + 30 * DAY);
  server.now = now + 30 * DAY;
  server.revision++;
  before = server.requests.length;
  const prev = link();
  await vault.sync();
  // (The server's features are asked again: they are kept for an hour.)
  expect(requestsSince(before).filter((r) => r !== "GET /config")).toStrictEqual(["GET /sync", `POST /vaults/${V}/trash/purge`]);
  const purge = purges()[0]!;
  expect(purge.body.items).toStrictEqual([
    { id: "i1", revision: expect.any(Number) },
    { id: "i2", revision: expect.any(Number) },
    { id: "i3", revision: expect.any(Number) },
  ]);
  expect(purge.body.manifests).toStrictEqual([{ vault_id: V, seq: 5, prev, sealed: row().manifest }]);
  expect(server.manifestErrors).toStrictEqual([]);
  expect(server.items.map((i) => i.id).sort()).toStrictEqual(["i4"]);
  // Shown without asking: the rows are gone from the copy, the manifest and its version and link kept.
  expect((await stored())?.items.map((r) => r.id).sort()).toStrictEqual(["i4"]);
  expect(await storedRow()).toMatchObject({ manifest: row().manifest, manifest_seq: 5, manifest_prev: prev });
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 5, link: link() } });
  expect((await memory()).trashSeen).toBeUndefined();
  // The next delta (it lists them as deleted) matches.
  server.editElsewhere("i4", { notes: "x" });
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect(purges()).toHaveLength(1);
});

test("REVIEW (old trash): a server's word alone never empties the trash: not its clock, not its setting, not a row's deleted_at, not a clock far from this browser's", async () => {
  const now = 1_800_000_000;
  const purges = () => sent("POST", `/vaults/${V}/trash/purge`);
  const lies: Record<string, () => void> = {
    "a clock at the end of time": () => {
      server.now = Number.MAX_SAFE_INTEGER;
      server.trashDays = 1;
    },
    "a clock a year ahead": () => {
      server.now = now + 365 * DAY;
      server.trashDays = 30;
    },
    "the shortest setting": () => {
      server.now = now;
      server.trashDays = 1;
    },
    "items deleted long ago, it says": () => {
      server.now = now;
      server.trashDays = 30;
      for (const i of server.items) if (i.deleted_at) i.deleted_at = 5;
      server.remanifest(V);
    },
  };
  for (const [name, lie] of Object.entries(lies)) {
    at(now);
    await signedIn({ items: 3 });
    server.now = now;
    // Trashed a moment ago (by another device); this browser has just seen them there.
    server.trashElsewhere("i1", now - 10);
    server.trashElsewhere("i2", now - 10);
    await vault.sync();
    lie();
    server.revision++;
    server.bump(V);
    server.follow(V);
    await vault.sync();
    await vault.sync();
    expect(purges(), name).toHaveLength(0);
    expect(server.items, name).toHaveLength(3);
    expect(vault.manifestSummary(), name).toBe(null);
  }
  // A clock a year ahead, kept up for the whole period by this browser's clock: the two clocks still disagree.
  at(now);
  await signedIn({ items: 3 });
  server.trashDays = 30;
  server.now = now + 365 * DAY;
  server.trashElsewhere("i1", now - 10);
  await vault.sync();
  at(now + 31 * DAY);
  server.now = now + 396 * DAY;
  server.revision++;
  await vault.sync();
  expect(purges()).toHaveLength(0);
  // An item that left the trash and came back is watched from the start again.
  at(now);
  await signedIn({ items: 3 });
  server.now = now;
  server.trashDays = 30;
  server.trashElsewhere("i1", now - 40 * DAY);
  await vault.sync();
  at(now + 20 * DAY);
  server.now = now + 20 * DAY;
  serverItem("i1").deleted_at = null;
  serverItem("i1").revision = ++server.revision;
  serverItem("i1").seq = server.bump(V);
  server.follow(V);
  await vault.sync();
  server.trashElsewhere("i1", now - 40 * DAY);
  await vault.sync();
  at(now + 31 * DAY);
  server.now = now + 31 * DAY;
  server.revision++;
  await vault.sync();
  expect(purges()).toHaveLength(0);
  expect((await memory()).trashSeen).toStrictEqual({ i1: now + 20 * DAY });
});

test("old trash: nothing with trash kept forever or read access; one request of at most the server's batch size (never more than 250) per sync; a failure is ignored and not repeated", async () => {
  const now = 1_800_000_000;
  const purges = () => sent("POST", `/vaults/${V}/trash/purge`);
  /** Three items in the trash for 90 days, which this browser has watched there for 31. */
  const watched = async (setup: () => void) => {
    at(now - 31 * DAY);
    await signedIn({
      items: 3,
      before: () => {
        server.now = now - 31 * DAY;
        for (const id of ["i1", "i2", "i3"]) server.trashElsewhere(id, now - 90 * DAY);
        setup();
      },
    });
    expect(purges()).toHaveLength(0);
    at(now);
    server.now = now;
    server.revision++;
    await vault.sync();
  };
  // Kept forever.
  await watched(() => {});
  expect(purges()).toHaveLength(0);
  // Read access.
  await watched(() => {
    server.trashDays = 30;
    row().role = "read";
  });
  expect(purges()).toHaveLength(0);
  // The admin's batch limit: one request per sync, the rest at the next one.
  await watched(() => {
    server.trashDays = 30;
    server.limits = { max_import_items: 2 };
  });
  expect(purges().map((r) => r.body.items.length)).toStrictEqual([2]);
  server.revision++;
  await vault.sync();
  expect(purges().map((r) => r.body.items.length)).toStrictEqual([2, 1]);
  expect(server.items).toStrictEqual([]);
  expect(server.manifestErrors).toStrictEqual([]);
  // Refused (another device was faster, say): ignored, the sync still succeeds, and the same state isn't tried twice.
  await watched(() => {
    server.trashDays = 30;
    server.handlers[`POST /vaults/${V}/trash/purge`] = () => ({ status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } });
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
  // What the server sent is noted beside the rows (never on the row, where a server could put it too).
  expect((await stored())?.served).toStrictEqual({ i1: dataHash(old.data) });
  expect(SERVED_HASH in (await storedItem("i1"))).toBe(false);
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

// ------------------------------------------------------------ review fixes

/** The server's whole state, to go back to: a server that forks answers from an older state and lets another device write on from there. */
const saveServer = () => structuredClone({ items: server.items, vaults: server.vaults, tombstones: server.tombstones, logs: server.logs });
/** The server answers from `saved` again (served as a change, so this browser asks and gets it). */
function restoreServer(saved: ReturnType<typeof saveServer>) {
  const revision = server.revision;
  Object.assign(server, structuredClone(saved));
  server.revision = revision + 10;
}
const logRequests = () => sent("GET", `/vaults/${V}/manifest-log`);
const failing = () => ({ status: 500, body: { error: "internal", message: "no" } });

test("REVIEW PoC (R2): a /sync row that carries served_sha256 with other data is a mismatch; the field never reaches the copy", async () => {
  await signedIn();
  const real = serverItem("i1").data;
  // The server serves an older ciphertext of the item and "explains" it with this browser's own marker.
  const older = JSON.stringify({ ...JSON.parse(real), notes: "an older version" });
  server.handlers["GET /sync"] = (req) => {
    const answer = server.syncAnswer(req.query) as { items: Record<string, unknown>[] };
    for (const r of answer.items) if (r.id === "i1") Object.assign(r, { data: older, [SERVED_HASH]: dataHash(real) });
    return { body: answer };
  };
  tamper(() => (serverItem("i1").seq = (row().seq ?? 0) + 1));
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
  const copy = await stored();
  expect(
    copy?.items.some((r) => SERVED_HASH in r),
    "deleted from the rows",
  ).toBe(false);
  expect(copy?.served, "and never taken for a kept copy").toBeUndefined();
  // The same at first sight (a new browser: a full answer, nothing remembered).
  await vault.lockAll();
  fake = installChrome();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(warned()).toStrictEqual([V]);
  // A marker left on a row of an offline copy (an older build wrote it there) is dropped too, not believed.
  delete server.handlers["GET /sync"];
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  await vault.lockAll();
  const kept = (await stored())!;
  Object.assign(kept.items.find((r) => r.id === "i1")!, { data: older, [SERVED_HASH]: dataHash(real) });
  await storage.syncCache.set("a1", kept);
  await reopen(false);
  expect(vault.getEntry("i1")?.item.notes).toBe("an older version");
  await expectReject(vault.createItem(login("New")), (e) => e.message === UNREACHABLE_TEXT);
  await reopen();
  await vault.sync();
  expect(vault.getEntry("i1")?.item.notes, "the whole vault was fetched").toBe("");
  expect(warned()).toStrictEqual([]);
});

test("REVIEW (fork then join): a server that moves this browser onto another history at the same or a higher version is refused, with and without the log", async () => {
  await signedIn();
  const fork = saveServer();
  // This browser writes version 2 and remembers it (version and link).
  const id = await vault.createItem(login("Laptop's new item"));
  await vault.sync();
  const mine = (await memory()).manifests![V]!;
  expect(mine).toStrictEqual({ version: 2, link: link() });
  // The server went on showing another device version 1; that device wrote its own version 2 from there.
  restoreServer(fork);
  server.editElsewhere("i1", { notes: "phone" });
  expect(row().manifest_seq).toBe(2);
  expect(link()).not.toBe(mine.link);
  // Joined at the same version: another manifest at the version this browser remembers. No log is needed to see it.
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(logRequests()).toHaveLength(0);
  expect(vault.getEntry(id), "the vault is shown as the server has it").toBeUndefined();
  expect((await memory()).manifests![V], "nothing is remembered from it").toStrictEqual(mine);
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);

  // Joined one and two versions later: the log decides, and the other history's log doesn't lead back to what this browser saw.
  for (const _step of [3, 4]) {
    server.editElsewhere("i2", { notes: "phone again" });
    const asked = logRequests().length;
    await vault.sync();
    expect(
      logRequests()
        .slice(asked)
        .map((r) => r.query),
      "the log after the remembered version",
    ).toStrictEqual([{ after: "2" }, { after: "2" }]);
    expect(warned()).toStrictEqual([V]);
    expect((await memory()).manifests![V]).toStrictEqual(mine);
  }
  // A log that lists both histories (this browser's own version 2 among the other's entries) doesn't connect either.
  const own = { seq: 2, prev: fork.logs[V]![0] ? manifestLink(1, ZERO_LINK, fork.vaults[0]!.manifest!) : ZERO_LINK, digest: "x".repeat(43) };
  server.handlers[`GET /vaults/${V}/manifest-log`] = () => ({ body: { entries: [...server.logs[V]!, own], more: false } });
  server.revision++;
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // Without the log, as an answer: there is none for this browser (404), or the request is refused (400): a mismatch.
  for (const status of [404, 400]) {
    server.handlers[`GET /vaults/${V}/manifest-log`] = () => ({ status, body: { error: "not_found", message: "no" } });
    server.revision++;
    await vault.sync();
    expect(warned(), String(status)).toStrictEqual([V]);
  }
  expect((await memory()).manifests![V], "never moved onto the other history").toStrictEqual(mine);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("REVIEW (the chain): a manifest several steps ahead on this browser's own history checks out through the log, page by page; more than five pages don't connect", async () => {
  await signedIn();
  for (let n = 0; n < 4; n++) server.editElsewhere("i1", { notes: `edit ${n}` });
  server.logPage = 1;
  await vault.sync();
  // Versions 2…5 after the remembered 1, one entry an answer: four requests, each from the last entry seen.
  expect(logRequests().map((r) => r.query.after)).toStrictEqual(["1", "2", "3", "4"]);
  expect(warned()).toStrictEqual([]);
  expect(await versions()).toStrictEqual({ [V]: 5 });
  // One step ahead needs no log at all.
  server.editElsewhere("i1", { notes: "one more" });
  await vault.sync();
  expect(logRequests().length).toBe(4);
  // Seven steps ahead with one entry an answer: the fifth answer still says "more". The log doesn't connect.
  for (let n = 0; n < 7; n++) server.editElsewhere("i2", { notes: `edit ${n}` });
  const asked = logRequests().length;
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // Five for the delta, five for the full answer that decides.
  expect(logRequests().length - asked).toBe(10);
  expect(await versions()).toStrictEqual({ [V]: 6 });
  // With the whole log in one answer it connects, and the warning goes by itself.
  server.logPage = 2000;
  server.revision++;
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(await versions()).toStrictEqual({ [V]: 13 });
});

test("REVIEW (the chain): when the log can't be fetched the answer isn't used: the previous copy and state stay, no warning, writes wait; the next sync decides", async () => {
  await signedIn();
  const before = { ids: ids(), row: await storedRow(), memory: await memory(), notes: vault.getEntry("i1")?.item.notes };
  server.editElsewhere("i1", { notes: "phone" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  server.handlers[`GET /vaults/${V}/manifest-log`] = failing;
  for (const answer of [failing, () => ({ status: 429, body: { error: "rate_limited", message: "slow down" } }), () => ({ status: 503, body: "<html>" })]) {
    server.handlers[`GET /vaults/${V}/manifest-log`] = answer as never;
    await expect(vault.sync(), "the sync has failed").rejects.toThrow();
    expect(warned(), "no warning").toStrictEqual([]);
    // Nothing of the answer is shown or kept: not the new rows with the old state, not the new manifest.
    expect(ids()).toStrictEqual(before.ids);
    expect(vault.getEntry("i1")?.item.notes).toBe(before.notes);
    expect(await storedRow()).toStrictEqual(before.row);
    expect(await memory()).toStrictEqual(before.memory);
  }
  // Writes into the vault wait for a sync that gets through; nothing is sent meanwhile (not built on the old state).
  const writes = () => server.requests.filter((r) => r.method !== "GET").length;
  const entry = vault.getEntry("i1")!;
  for (const write of [() => vault.createItem(login("New")), () => vault.updateItem(entry, { ...entry.item, notes: "x" }), () => vault.trashItem(entry)]) await expect(write()).rejects.toThrow();
  expect(writes()).toBe(0);
  // The network down altogether is the same thing.
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) =>
    String(input).includes("manifest-log") ? Promise.reject(new TypeError("Failed to fetch")) : server.fetch(input, init),
  );
  await expectReject(vault.sync(), (e) => e.message === UNREACHABLE_TEXT);
  expect(warned()).toStrictEqual([]);
  expect(ids()).toStrictEqual(before.ids);
  // The log answers again: the same answer is checked and used, and writes go on.
  vi.stubGlobal("fetch", server.fetch);
  delete server.handlers[`GET /vaults/${V}/manifest-log`];
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(ids()).toStrictEqual(["i1", "i2", "i3"]);
  expect(vault.getEntry("i1")?.item.notes).toBe("phone");
  expect(await versions()).toStrictEqual({ [V]: 3 });
  await vault.createItem(login("New"));
  expect(server.manifestErrors).toStrictEqual([]);
});

test("REVIEW (a hidden item): a live item the server makes unreadable (a wrong item_key) or sends without data is a mismatch: the popup's summary names the vault and writes are held", async () => {
  const hides: Record<string, () => void> = {
    "a wrong item_key (which the manifest doesn't cover)": () => {
      Object.assign(serverItem("i1"), { item_key: "not-the-key", seq: (row().seq ?? 0) + 1, revision: server.revision + 1 });
    },
    "a live row without data, with its right hash": () => {
      server.handlers["GET /sync"] = (req) => {
        const answer = server.syncAnswer(req.query) as { items: Record<string, unknown>[] };
        for (const r of answer.items) if (r.id === "i1") Object.assign(r, { data: undefined, item_key: undefined, data_sha256: dataHash(serverItem("i1").data) });
        return { body: answer };
      };
      serverItem("i1").seq = (row().seq ?? 0) + 1;
    },
  };
  for (const [name, hide] of Object.entries(hides)) {
    await signedIn();
    expect(ids()).toStrictEqual(["i1", "i2"]);
    tamper(hide);
    await vault.sync();
    expect(ids(), name).toStrictEqual(["i2"]);
    expect(vault.manifestSummary(), name).toStrictEqual({ text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [{ id: V, name: "Personal" }], key: `["${V}"]` });
    await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
    expect(await versions(), `${name}: nothing new is remembered`).toStrictEqual({ [V]: 1 });
    // The same for a browser that sees the vault for the first time.
    await vault.lockAll();
    fake = installChrome();
    await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
    expect(warned(), `${name}: first sight`).toStrictEqual([V]);
    expect(await versions(), name).toBeUndefined();
  }
});

test("REVIEW (deleted_at): in the trash is exactly 'deleted_at is not null'; a row with deleted_at 0 is never shown as live and makes the vault a mismatch", async () => {
  await signedIn({ items: 3 });
  server.trashElsewhere("i3");
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i2"]);
  // The manifest counts i3 as trashed; the server sends its row (whole) with `deleted_at: 0`.
  server.handlers["GET /sync"] = (req) => {
    const answer = server.syncAnswer({ ...req.query, trash: "" }) as { items: Record<string, unknown>[] };
    for (const r of answer.items) if (r.id === "i3") r.deleted_at = 0;
    return { body: answer };
  };
  tamper(() => (serverItem("i3").seq = (row().seq ?? 0) + 1));
  await vault.sync();
  expect(ids(), "not a live item").toStrictEqual(["i1", "i2"]);
  expect(vault.getEntry("i3")).toBeUndefined();
  expect(warned()).toStrictEqual([V]);
});

test("REVIEW (numbers): an answer with a vault number, manifest version, key epoch or deleted_at that isn't a whole number is not used at all", async () => {
  await signedIn();
  const shown = { ids: ids(), row: await storedRow() };
  const breaks: Record<string, (a: { vaults: Record<string, unknown>[]; items: Record<string, unknown>[] }) => void> = {
    "seq 1.5": (a) => (a.vaults[0]!.seq = 1.5),
    "manifest_seq 2^53": (a) => (a.vaults[0]!.manifest_seq = 2 ** 53),
    "manifest_seq -1": (a) => (a.vaults[0]!.manifest_seq = -1),
    "key_epoch 0.5": (a) => (a.vaults[0]!.key_epoch = 0.5),
    "deleted_at 1e300": (a) => (a.items[0]!.deleted_at = 1e300),
    "deleted_at -5": (a) => (a.items[0]!.deleted_at = -5),
  };
  for (const [name, fn] of Object.entries(breaks)) {
    server.handlers["GET /sync"] = (req) => {
      const answer = server.syncAnswer({ ...req.query, since: "" }) as never;
      fn(answer);
      return { body: answer };
    };
    server.editElsewhere("i1", { notes: name });
    await expectReject(vault.sync(), (e) => e.message.includes("unexpected answer"));
    expect(ids(), name).toStrictEqual(shown.ids);
    expect(await storedRow(), name).toStrictEqual(shown.row);
    expect(warned(), name).toStrictEqual([]);
  }
});

test("REVIEW (an answer behind an own write): it isn't used; the whole vault is asked for again, twice at most, and an answer that stays behind is judged as it is (a rollback)", async () => {
  // A stale answer once (read before the write): asked again, then all is well. No warning, nothing lost.
  await signedIn();
  const stale = server.syncAnswer({ trash: "summary" });
  const id = await vault.createItem(login("New"));
  expect((await stored())?.own).toStrictEqual({ [V]: 4 });
  let served = 0;
  server.handlers["GET /sync"] = () => (served++ === 0 ? { body: { ...stale, revision: server.revision } } : undefined);
  let before = syncs().length;
  await vault.sync();
  expect(syncs().length - before, "the stale answer, then everything").toBe(2);
  expect(syncs().at(-1)!.query.since, "in full").toBeUndefined();
  expect(vault.getEntry(id)?.item.name).toBe("New");
  expect(warned()).toStrictEqual([]);
  expect(await versions()).toStrictEqual({ [V]: 2 });

  // A server that stays behind (it went back to before this browser's write): never shown as "ok".
  await signedIn();
  const old = saveServer();
  const old_answer_revision = server.revision;
  const mine = await vault.createItem(login("New"));
  expect(vault.getEntry(mine)).toBeDefined();
  Object.assign(server, structuredClone(old));
  server.revision = old_answer_revision;
  before = syncs().length;
  await vault.sync();
  // The delta, then the whole vault twice more.
  expect(
    syncs()
      .slice(before)
      .map((r) => (r.query.since ? "delta" : "full")),
  ).toStrictEqual(["delta", "full", "full"]);
  expect(warned(), "the vault's manifest is older than the one this browser wrote").toStrictEqual([V]);
  expect(await versions(), "never lowered").toStrictEqual({ [V]: 2 });
  await expectReject(vault.createItem(login("Again")), (e) => e.message === MANIFEST_HELD_TEXT);
  // (This is the review's web PoC, as the extension sees it: a later write can't launder the rollback.)
  expect(server.requests.filter((r) => r.method === "POST" && r.path === "/items")).toHaveLength(1);
});

test("REVIEW (the 'log out' timeout): the manifest memory outlives the offline copy, so a server that went back while this browser was signed out is caught at the next sign-in", async () => {
  await signedIn();
  const old = saveServer();
  server.editElsewhere("i1", { notes: "new password" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  await vault.sync();
  const mine = (await memory()).manifests;
  expect(mine).toStrictEqual({ [V]: { version: 3, link: link() } });
  // The vault timeout with the "log out" action: the offline copy goes, the memory stays.
  await vault.logoutAll();
  expect(await stored()).toBeUndefined();
  expect((await memory()).manifests).toStrictEqual(mine);
  // The server serves the vault as it was at version 1 (consistent in itself) to the browser that signs in again.
  restoreServer(old);
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(warned()).toStrictEqual([V]);
  expect((await memory()).manifests).toStrictEqual(mine);
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
});

test("REVIEW (memory): the first format (a bare version in the offline copy) is nothing remembered; a record that can't be read is never taken for nothing, checked against or overwritten", async () => {
  // The first format: a number per vault, inside the offline copy. Read as nothing remembered; nothing breaks.
  await signedIn();
  server.editElsewhere("i1", { notes: "x" });
  await vault.sync();
  await vault.lockAll();
  const copy = (await stored())! as unknown as Record<string, unknown>;
  Object.assign(copy, { manifests: { [V]: 9 }, itemRevs: { i1: 7 } });
  await storage.syncCache.set("a1", copy as never);
  await storage.deviceMemory.clear("https://vault.test", "u-1");
  await reopen();
  await vault.sync();
  expect(warned(), "9 was never a version this browser checks against").toStrictEqual([]);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 2, link: link() } });
  expect((await memory()).itemRevs?.i1, "the item counters an older copy kept are taken over").toBe(7);
  expect((await stored()) as unknown as Record<string, unknown>).not.toHaveProperty("manifests");

  // A record that can't be read (damaged, or a newer format).
  for (const garbage of ["garbage", { v: 99, manifests: {} }]) {
    await signedIn({ manifest: false, before: () => (row().manifest_ok = true) });
    expect(row().manifest_seq).toBe(1);
    await vault.lockAll();
    await storage.deviceMemory.update("https://vault.test", "u-1", () => garbage);
    // The server takes its manifest away: with the memory unreadable this can't be told from a rollback.
    Object.assign(row(), { manifest: null, manifest_seq: 0, manifest_prev: null, manifest_ok: true });
    server.revision++;
    server.bump(V);
    const puts = sent("PUT", `/vaults/${V}/manifest`).length;
    await reopen();
    await vault.sync();
    expect(sent("PUT", `/vaults/${V}/manifest`).length, "no manifest is started").toBe(puts);
    expect(await storage.deviceMemory.read("https://vault.test", "u-1"), "never overwritten").toStrictEqual(garbage);
    // A vault with a manifest is never "ok" then: no warning, and nothing is written into it.
    server.remanifest(V, 1);
    server.revision++;
    server.bump(V);
    await vault.sync();
    expect(warned()).toStrictEqual([]);
    await expectReject(vault.createItem(login("New")), (e) => e.message.startsWith("PassAuth couldn't check this vault"));
    expect(sent("POST", "/items")).toHaveLength(0);
    expect(await storage.deviceMemory.read("https://vault.test", "u-1")).toStrictEqual(garbage);
    // What its own rows show is still said: a vault that doesn't match its manifest warns.
    tamper(() => {
      server.items = server.items.filter((i) => i.id !== "i1");
      server.tombstones.push({ id: "i1", vault_id: V, seq: (row().seq ?? 0) + 1 });
    });
    await vault.sync();
    expect(warned()).toStrictEqual([V]);
  }
});

test("REVIEW (no warning from bookkeeping): a copy that is behind what this browser remembers (the worker stopped between two writes) gets one full fetch, not a warning", async () => {
  await signedIn();
  await vault.lockAll();
  const copy = (await stored())!;
  // The memory was written, the copy that carries that version wasn't (or the other way round, below).
  server.editElsewhere("i1", { notes: "phone" });
  await reopen();
  await vault.sync();
  expect(await versions()).toStrictEqual({ [V]: 2 });
  await vault.lockAll();
  await storage.syncCache.set("a1", copy);
  const before = syncs().length;
  await reopen(false);
  expect(warned(), "offline: unchecked, no warning").toStrictEqual([]);
  expect(vault.getEntry("i1")?.item.notes, "the copy is still shown").toBe("");
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(
    syncs()
      .slice(before)
      .some((r) => !r.query.since),
    "everything was fetched",
  ).toBe(true);
  expect(vault.getEntry("i1")?.item.notes).toBe("phone");
  const atTwo = (await memory()).manifests!;
  expect(atTwo[V]!.version).toBe(2);
  // The copy ahead of the memory by more than one step: the log is asked at the sync, never a warning from the copy.
  server.editElsewhere("i1", { notes: "a" });
  server.editElsewhere("i1", { notes: "b" });
  await vault.sync();
  await vault.lockAll();
  await storage.deviceMemory.update("https://vault.test", "u-1", (m) => ({ ...(m as object), manifests: atTwo }));
  const asked = logRequests().length;
  await reopen(false);
  expect(warned()).toStrictEqual([]);
  await expectReject(vault.createItem(login("New")), (e) => e.message === UNREACHABLE_TEXT);
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(logRequests().length).toBeGreaterThan(asked);
  expect(await versions()).toStrictEqual({ [V]: 4 });
  await vault.createItem(login("New"));
  expect(server.manifestErrors).toStrictEqual([]);
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
