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
//
// And review round 2 (the tests named "ROUND 2", the re-review's PoCs among them): "Use the server's copy" here for
// every role (a local acceptance, nothing sent), no first manifest over an item that doesn't open, a way out when what
// this browser remembers can't be read, the strict trash rule with its floor, own writes shown only when the answer
// names the link sent, and no whole fetch at every sync or worker start while a warning stands.

import { beforeEach, expect, test, vi } from "vitest";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer, sessionKeys } from "./fake-server";
import { expectReject } from "./helpers";

vi.mock("../src/wasm/passauth_core", async () => (await import("./fake-core")).module());

const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures, SERVER_UPDATE_TEXT, UNREACHABLE_TEXT } = await import("../src/background/api");
const {
  MANIFEST_ACCEPT_ACTION,
  MANIFEST_ACCEPT_BODY,
  MANIFEST_ACCEPT_TITLE,
  MANIFEST_BUSY_TEXT,
  ITEM_LOCKED_TITLE,
  ITEM_NEWER_NOTE,
  ITEM_NEWER_TITLE,
  MANIFEST_CHANGED_TEXT,
  MANIFEST_FORGET_BODY,
  MANIFEST_HELD_TEXT,
  MANIFEST_ITEM_TEXT,
  MANIFEST_NOT_CHECKED_TEXT,
  MANIFEST_ITEM_WHERE_TEXT,
  MANIFEST_NOT_ACCEPTABLE_TEXT,
  MANIFEST_READER_TEXT,
  MANIFEST_REVIEW_TEXT,
  MANIFEST_UNCHECKED_TEXT,
  MANIFEST_WARNING_TEXT,
  MEMORY_RESET_ACTION,
  MEMORY_RESET_BODY,
  MEMORY_UNREADABLE_TEXT,
  SERVED_HASH,
} = await import("../src/background/manifests");
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
    manifests?: Record<string, { version?: number; link?: string; accepts?: number }>;
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
const warned = () =>
  vault
    .manifestSummary()
    ?.vaults.filter((v) => v.text === MANIFEST_WARNING_TEXT)
    .map((v) => v.id) ?? [];
/** The popup's line for the vault (what is wrong, and what is offered), without its id and name. */
const offered = () => {
  const v = vault.manifestSummary()?.vaults.find((x) => x.id === V);
  if (!v) return null;
  const { id: _id, name: _name, ...rest } = v;
  return rest;
};
/** What each kind of warning shows for an account that may write. */
const REVIEW = { text: MANIFEST_WARNING_TEXT, hint: MANIFEST_REVIEW_TEXT, open: true };
const ACCEPT = { text: MANIFEST_WARNING_TEXT, accept: true };
/** ROUND 3: accepting forgets (the server shows no record); a vault with an item that can't be opened (a notice, not a warning). */
const FORGET = { text: MANIFEST_WARNING_TEXT, accept: true, forget: true };
const ITEM = { text: MANIFEST_ITEM_TEXT, hint: MANIFEST_ITEM_WHERE_TEXT, open: true };
const CONFIRM = { action: MANIFEST_ACCEPT_ACTION, title: MANIFEST_ACCEPT_TITLE, body: MANIFEST_ACCEPT_BODY, forgetBody: MANIFEST_FORGET_BODY };
/** The vaults that show the warning (not those that only show the item notice). */
const itemNoticed = () =>
  vault
    .manifestSummary()
    ?.vaults.filter((v) => v.text === MANIFEST_ITEM_TEXT)
    .map((v) => v.id) ?? [];
/** A change on the server that the vault's manifest doesn't know of (what a dishonest server does): `fn`, served as a change. */
function tamper(fn: () => void) {
  fn();
  server.revision++;
  server.bump(V);
}
const serverItem = (id: string) => server.items.find((i) => i.id === id)!;
/** The device memory record "Reset on this device" put aside (undefined: none), read straight from the store. */
const asideRecord = () =>
  new Promise<unknown>((resolve, reject) => {
    const open = indexedDB.open("passauth", 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const t = open.result.transaction("sync", "readonly");
      const req = t.objectStore("sync").get("device-unreadable:https://vault.test|u-1");
      t.oncomplete = () => resolve(req.result);
      t.onerror = () => reject(t.error);
    };
  });

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

test("ROUND 2 (S6): an own write is shown as sent only when the answer's manifest_link is the link of the manifest sent; a version number alone decides nothing; else a sync follows and checks the vault", async () => {
  await signedIn();
  for (const patch of [{ manifest_link: "x".repeat(43) }, { manifest_link: undefined }, { manifest_link: null }]) {
    server.handlers["POST /items"] = (req) => {
      const r = server.route(req);
      return { ...r, body: { ...(r.body as object), ...patch } };
    };
    const before = server.requests.length;
    const id = await vault.createItem(login("New"));
    expect(requestsSince(before), JSON.stringify(patch)).toStrictEqual(["POST /items", "GET /sync"]);
    expect(vault.getEntry(id)?.item.name).toBe("New");
    expect(vault.manifestSummary()).toBe(null);
  }
  // The version named in the answer is not what counts: with the right link the write is shown without asking.
  for (const patch of [{ manifest_seq: 99 }, { manifest_seq: undefined }]) {
    server.handlers["POST /items"] = (req) => {
      const r = server.route(req);
      return { ...r, body: { ...(r.body as object), ...patch } };
    };
    const before = server.requests.length;
    await vault.createItem(login("New"));
    expect(requestsSince(before), JSON.stringify(patch)).toStrictEqual(["POST /items"]);
  }
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 6, link: link() } });
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 2 (S6, a create sent again): the first try was stored with its own sealing of the manifest and its answer got lost; the repeat's answer names that manifest, so nothing is remembered from the second sealing and no false warning follows", async () => {
  await signedIn();
  // The server holds the item with a manifest of version 2 that isn't the one this request seals (the lost first try
  // sealed its own), and answers this request as a repeat: nothing written, the vault's number and manifest as they are.
  server.handlers["POST /items"] = (req) => {
    const b = req.body as { id: string; vault_id: string; key: string; data: string; manifests: { seq: number }[] };
    expect(b.manifests[0]!.seq).toBe(2);
    server.items.push({ id: b.id, vault_id: V, item_key: b.key, data: b.data, revision: ++server.revision, deleted_at: null, seq: server.bump(V) });
    server.remanifest(V);
    return { body: { id: b.id, revision: server.revision, vault_seq: row().seq, manifest_seq: 2, manifest_link: link() } };
  };
  const before = server.requests.length;
  const id = await vault.createItem(login("Sent twice"));
  delete server.handlers["POST /items"];
  // The answer names version 2 and the next vault number, exactly like a stored write; only the link tells.
  expect(requestsSince(before)).toStrictEqual(["POST /items", "GET /sync"]);
  expect(vault.getEntry(id)?.item.name).toBe("Sent twice");
  expect((await memory()).manifests, "the server's link, not the second sealing's").toStrictEqual({ [V]: { version: 2, link: link() } });
  expect((await storedRow()).manifest).toBe(row().manifest);
  // No mismatch at the next sync, at a restart, or for the next write.
  server.revision++;
  await vault.sync();
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  await vault.createItem(login("Next"));
  expect(warned()).toStrictEqual([]);
  expect(server.manifestErrors).toStrictEqual([]);
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
    // The served copy doesn't check out on its own either: nothing to accept here; reviewed in the web vault.
    const notice = vault.manifestSummary();
    expect(notice, name).toStrictEqual({
      vaults: [{ id: V, name: "Personal", ...REVIEW }],
      key: `[["${V}",0,0]]`,
      confirm: CONFIRM,
    });
    expect(vault.manifestWarned(V), name).toBe(true);
    expect(vault.manifestWarning(V), name).toBe(`${MANIFEST_WARNING_TEXT} ${MANIFEST_REVIEW_TEXT}`);
    await expectReject(vault.acceptServerCopy(V), (e) => e.message === `${MANIFEST_NOT_ACCEPTABLE_TEXT} ${MANIFEST_REVIEW_TEXT}`);
    expect(warned(), name).toStrictEqual([V]);
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
    // ROUND 2 (S7): the warning was raised by a server's whole answer and is kept with the copy: after a restart
    // (also without the server) it is there at once, writes are held, and nothing is fetched in full to find it again.
    await reopen(false);
    expect(warned(), name).toStrictEqual([V]);
    expect(offered(), name).toStrictEqual(REVIEW);
    await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
    const fetched = syncs().length;
    await reopen();
    await vault.sync();
    expect(warned(), name).toStrictEqual([V]);
    expect(
      syncs()
        .slice(fetched)
        .every((r) => !!r.query.since),
      `${name}: only deltas while the warning stands`,
    ).toBe(true);
    // It is gone by itself once an answer matches again: the server shows the record it had (where it lied about
    // the record itself), and someone used "Use the server's copy" in the web vault (a new baseline on that record,
    // one version above it).
    Object.assign(row(), honest);
    server.revision++;
    server.bump(V);
    server.remanifest(V);
    await vault.sync();
    expect(warned(), name).toStrictEqual([]);
    expect(await versions(), name).toStrictEqual({ [V]: 3 });
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
  // (After a restart the warning is there from the copy: it was raised by a whole answer, for the vault row it holds.)
  await reopen(false);
  expect(warned()).toStrictEqual([V]);
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
const saveServer = () => structuredClone({ items: server.items, vaults: server.vaults, tombstones: server.tombstones, logs: server.logs, revision: server.revision });
/**
 * The server answers from `saved` again, like a real database put back: its rows, records, logs AND the account's
 * sync revision are the old ones (ROUND 3, T2: the earlier helper raised the revision, "served as a change", which no
 * restored server does, and so hid that a lower revision was dropped unseen).
 */
function restoreServer(saved: ReturnType<typeof saveServer>) {
  Object.assign(server, structuredClone(saved));
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
  // (The server stops lying without anything changing: a delta brings nothing and the warning stands, ROUND 2 S7;
  // "Use the server's copy" fetches everything, finds the vault in order and is done, with nothing accepted.)
  delete server.handlers["GET /sync"];
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  await vault.acceptServerCopy(V);
  expect(warned()).toStrictEqual([]);
  expect((await memory()).manifests, "an ordinary 'ok': no acceptance counted").toStrictEqual({ [V]: { version: 1, link: link() } });
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

  // Joined one version later: its predecessor isn't the remembered manifest, a mismatch at once (ROUND 2: no log is
  // asked for one step). Two versions later: the log decides, and the other history's log doesn't lead back to what
  // this browser saw. (One log request per sync: the vault shows its warning already, so nothing is fetched in full.)
  for (const [step, logs] of [
    [3, []],
    [4, [{ after: "2" }]],
  ] as const) {
    server.editElsewhere("i2", { notes: "phone again" });
    expect(row().manifest_seq).toBe(step);
    const asked = logRequests().length;
    const fetched = syncs().length;
    await vault.sync();
    expect(
      logRequests()
        .slice(asked)
        .map((r) => r.query),
      "the log after the remembered version",
    ).toStrictEqual(logs);
    expect(syncs().length - fetched, "one delta").toBe(1);
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
  // ROUND 2 (S1): only the user can move this browser onto the other history. The served copy checks out on its own,
  // so "Use the server's copy" is offered, and accepting replaces what is remembered (counted: `accepts`).
  expect(offered()).toStrictEqual(ACCEPT);
  await vault.acceptServerCopy(V);
  expect(warned()).toStrictEqual([]);
  expect((await memory()).manifests![V]).toStrictEqual({ version: 4, link: link(), accepts: 1 });
  delete server.handlers[`GET /vaults/${V}/manifest-log`];
  await vault.createItem(login("New"));
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
  // With the whole log in one answer it connects, and the warning goes by itself (the delta is still judged).
  // ROUND 2 (S9): things in the list that are no entries are left out, never fatal.
  server.logPage = 2000;
  server.handlers[`GET /vaults/${V}/manifest-log`] = (req) => {
    const real = (server.route(req).body as { entries: unknown[] }).entries;
    return { body: { entries: [null, 7, "x", { seq: "3" }, ...real, { seq: 99, prev: 1, digest: null }, []], more: false } };
  };
  server.revision++;
  const fetched = syncs().length;
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(syncs().length - fetched, "one delta, no whole fetch").toBe(1);
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

test("ROUND 3 PoC 1 (T1a; was: the user is told to delete it): a server that sends an item this browser shows with another item_key (the record doesn't cover the key) changes nothing here: the item stays shown and writable with this browser's own key, nothing is warned, listed or held", async () => {
  await signedIn();
  const mine = (await storedItem("i1")).item_key;
  // Only the key is replaced; the data, which the vault's record covers, is the same.
  tamper(() => Object.assign(serverItem("i1"), { item_key: "not-the-key", seq: (row().seq ?? 0) + 1, revision: server.revision + 1 }));
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i2"]);
  expect(vault.getEntry("i1")?.item.name).toBe("Item 1");
  expect(vault.manifestSummary(), "no warning, no notice").toBe(null);
  expect(vault.otherItems()).toStrictEqual([]);
  // The copy keeps this browser's key for the row (with the server's revision), also across a whole answer and a restart.
  expect(await storedItem("i1")).toMatchObject({ item_key: mine, data: serverItem("i1").data, revision: serverItem("i1").revision });
  await reopen();
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i2"]);
  expect(vault.manifestSummary()).toBe(null);
  expect((await storedItem("i1")).item_key).toBe(mine);
  // Nothing is held: other writes into the vault go through, and so does an edit of the item itself, which puts
  // this browser's key back on the server (the row every other device gets).
  await vault.createItem(login("New"));
  const entry = vault.getEntry("i1")!;
  await vault.updateItem(entry, { ...entry.item, notes: "still mine" });
  expect(serverItem("i1").item_key).toBe(mine);
  expect(JSON.parse(serverItem("i1").data).notes).toBe("still mine");
  expect(vault.manifestSummary()).toBe(null);
  expect(server.manifestErrors).toStrictEqual([]);
  // The same in the trash, on a server that sends the trash whole: no notice for a row this browser opened before.
  await signedIn({ features: FEATURES.filter((f) => f !== "delta_sync"), before: () => server.trashElsewhere("i2") });
  expect(vault.manifestSummary()).toBe(null);
  tamper(() => Object.assign(serverItem("i2"), { item_key: "not-the-key", revision: server.revision + 1 }));
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
});

test("ROUND 3 (T1c; was: a mismatch that held every write): an item that can't be decrypted and that this browser has no copy to go on with is listed as 'Item that can't be opened' (with its last known name), its vault shows the notice without an instruction to delete, and every write still goes through", async () => {
  const hides: Record<string, { hide: () => void; known: boolean }> = {
    "a wrong item_key and other data (the item was changed and its key damaged)": {
      hide: () => {
        server.editElsewhere("i1", { notes: "changed" });
        Object.assign(serverItem("i1"), { item_key: "not-the-key" });
      },
      known: true,
    },
    "a live row without data, with its right hash": {
      hide: () => {
        server.handlers["GET /sync"] = (req) => {
          const answer = server.syncAnswer(req.query) as { items: Record<string, unknown>[] };
          for (const r of answer.items) if (r.id === "i1") Object.assign(r, { data: undefined, item_key: undefined, data_sha256: dataHash(serverItem("i1").data) });
          return { body: answer };
        };
        serverItem("i1").seq = (row().seq ?? 0) + 1;
        server.revision++;
        server.bump(V);
      },
      known: true,
    },
  };
  for (const [name, { hide }] of Object.entries(hides)) {
    await signedIn();
    expect(ids()).toStrictEqual(["i1", "i2"]);
    hide();
    await vault.sync();
    expect(ids(), name).toStrictEqual(["i2"]);
    // Listed, with the name the copy this browser opened before had.
    const listed = [{ id: "i1", title: ITEM_LOCKED_TITLE, name: "Item 1", vaultName: "Personal" }];
    expect(vault.otherItems(), name).toStrictEqual(listed);
    // The notice: what is wrong, and for an account that may write where the item can be deleted. Not a warning:
    // nothing to accept, the item pages of the vault say nothing, and the vault's record is remembered as checked.
    expect(vault.manifestSummary()?.vaults, name).toStrictEqual([{ id: V, name: "Personal", ...ITEM }]);
    expect(MANIFEST_ITEM_TEXT, "no instruction to delete").not.toMatch(/[Dd]elete/);
    expect([warned(), itemNoticed()], name).toStrictEqual([[], [V]]);
    expect([vault.manifestWarned(V), vault.manifestWarning(V)], name).toStrictEqual([false, null]);
    await vault.acceptServerCopy(V);
    expect(itemNoticed(), `${name}: "Use the server's copy" has nothing to do`).toStrictEqual([V]);
    expect((await versions())?.[V], name).toBe(row().manifest_seq);
    // Writes are not held.
    const id = await vault.createItem(login("New"));
    const entry = vault.getEntry(id)!;
    await vault.updateItem(entry, { ...entry.item, notes: "x" });
    await vault.trashItem(vault.getEntry(id)!);
    expect(server.manifestErrors, name).toStrictEqual([]);
    expect(itemNoticed(), name).toStrictEqual([V]);
    // A worker restart (also without the server): still listed with its name (the last opened copy stays aside,
    // encrypted, in the offline copy), still the notice, still writable.
    await reopen(false);
    expect(vault.otherItems(), name).toStrictEqual(listed);
    expect(itemNoticed(), name).toStrictEqual([V]);
    await reopen();
    await vault.sync();
    expect(vault.otherItems(), name).toStrictEqual(listed);
    await vault.createItem(login("Another"));
    // A browser that sees the vault for the first time has no name for it; the same notice, the same freedom.
    await vault.lockAll();
    fake = installChrome();
    await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
    await fake.session.set({ "unlocked:a1": sessionKeys() });
    expect(await vault.ensureUnlocked()).toBe(true);
    expect(vault.otherItems(), `${name}: first sight`).toStrictEqual([{ id: "i1", title: ITEM_LOCKED_TITLE, vaultName: "Personal" }]);
    expect([warned(), itemNoticed()], `${name}: first sight`).toStrictEqual([[], [V]]);
    expect((await versions())?.[V], name).toBe(row().manifest_seq);
    await vault.createItem(login("From the new browser"));
    expect(server.manifestErrors, name).toStrictEqual([]);
    // A reader gets the notice alone.
    delete server.handlers["GET /sync"];
  }
  await signedIn({
    before: () => {
      Object.assign(serverItem("i1"), { item_key: "not-the-key" });
      row().role = "read";
    },
  });
  expect(offered()).toStrictEqual({ text: MANIFEST_ITEM_TEXT });
  // The item opens again (its key was put right elsewhere): the row and the notice go by themselves.
  await signedIn({ before: () => Object.assign(serverItem("i1"), { item_key: "not-the-key" }) });
  expect(itemNoticed()).toStrictEqual([V]);
  tamper(() => Object.assign(serverItem("i1"), { item_key: `${row().wrapped_key}:i1`, seq: (row().seq ?? 0) + 1, revision: server.revision + 1 }));
  await vault.sync();
  expect([ids(), vault.otherItems(), vault.manifestSummary()]).toStrictEqual([["i1", "i2"], [], null]);
  expect((await stored())?.stash).toBeUndefined();
});

test("ROUND 3 (T1b): an item that decrypts but isn't one this version reads (a type or format from a newer app) is listed as 'Item from a newer version of PassAuth' with 'Update PassAuth to see this item.': no notice, nothing held, it counts in the vault's record like any row, and it doesn't block a first manifest", async () => {
  const NEWER = "{ an item of a kind this version doesn't read";
  const listed = [{ id: "i3", title: ITEM_NEWER_TITLE, note: ITEM_NEWER_NOTE, vaultName: "Personal" }];
  await signedIn();
  server.addElsewhere("i3", V, NEWER);
  await vault.sync();
  expect(ids()).toStrictEqual(["i1", "i2"]);
  expect(vault.otherItems()).toStrictEqual(listed);
  expect(vault.manifestSummary(), "no warning and no notice").toBe(null);
  expect(await versions()).toStrictEqual({ [V]: 2 });
  // Writes go on, each with a manifest that counts the row (the fake server checks them with the real core).
  const id = await vault.createItem(login("New"));
  await vault.trashItem(vault.getEntry(id)!);
  expect(server.manifestErrors).toStrictEqual([]);
  await reopen(false);
  expect([vault.otherItems(), vault.manifestSummary()]).toStrictEqual([listed, null]);
  // No manifest yet: the first one is started over it (the row is counted by its data, which is authentic).
  await signedIn({
    manifest: false,
    before: () => {
      row().manifest_ok = true;
      server.addElsewhere("i3", V, NEWER);
    },
  });
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`)).toHaveLength(1);
  expect(row().manifest_seq).toBe(1);
  expect([vault.otherItems(), vault.manifestSummary()]).toStrictEqual([listed, null]);
  expect(server.manifestErrors).toStrictEqual([]);
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
    server.remanifest(V);
    server.revision++;
    server.bump(V);
    await vault.sync();
    expect(warned()).toStrictEqual([]);
    await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_UNCHECKED_TEXT || e.message === MEMORY_UNREADABLE_TEXT);
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

test("ROUND 2 the popup: each warned vault with what it offers ('Use the server's copy' when the served copy checks out, else where to go; an item that can't be opened; the memory reset); a refused server says so", async () => {
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { createElement } = await import("react");
  const { Notices } = await import("../src/popup/notices");
  const ctx = { signIns: null, state: { server: "https://vault.test" }, go: () => {}, notify: () => {} } as never;
  const confirm = CONFIRM;
  const render = (data: unknown) => renderToStaticMarkup(createElement(Notices, { ctx, data: data as never, tabId: undefined }));
  const WARNING = "Your server&#x27;s copy of this vault doesn&#x27;t match its record of changes. Items may be missing, restored or out of date.";
  // Not acceptable, with write access: reviewed elsewhere.
  const review = render({ manifest: { vaults: [{ id: V, name: "Personal", ...REVIEW }], key: "k", confirm } });
  expect(review).toContain("Personal");
  expect(review).toContain(WARNING);
  expect(review).toContain("Open the web vault or the desktop app to review this vault.");
  expect(review).toContain(">Open the web vault<");
  expect(review).not.toContain("Use the server");
  expect(review, "it can't be dismissed").not.toContain("Dismiss");
  // Acceptable (any role): the action, which asks first (the dialog isn't open yet).
  const accept = render({ manifest: { vaults: [{ id: V, name: "Team", ...ACCEPT }], key: "k", confirm } });
  expect(accept).toContain(WARNING);
  expect(accept).toContain("Use the server&#x27;s copy…");
  expect(accept).not.toContain("Open the web vault");
  expect(accept).not.toContain("PassAuth will accept this vault");
  // A reader of a vault that can't be accepted as it is; an item that can't be opened, for a writer and a reader.
  const others = render({
    manifest: {
      vaults: [
        { id: "a", name: "Read", text: MANIFEST_WARNING_TEXT, hint: MANIFEST_READER_TEXT },
        { id: "b", name: "Broken", ...ITEM },
        { id: "c", name: "Broken too", text: MANIFEST_ITEM_TEXT },
      ],
      key: "k",
      confirm,
    },
  });
  expect(others).toContain("Someone who can edit this vault can review it.");
  // ROUND 3 (T1): the notice gives no instruction to delete; a writer is told where the item can be deleted.
  expect(others).toContain("</strong>: An item in this vault can&#x27;t be opened. It can be deleted for good in the web vault or the desktop app. ");
  expect(others).toContain("Broken too</strong>: An item in this vault can&#x27;t be opened. <");
  expect(others).not.toContain("Delete it");
  // ROUND 3 (T3): a vault the server shows no record of is offered like any acceptable one (its confirmation differs:
  // `ManifestLines` shows `confirm.forgetBody` for it and sends `forget`); afterwards the quiet note, which stays.
  const forget = render({ manifest: { vaults: [{ id: V, name: "Personal", ...FORGET }], key: "k", confirm } });
  expect(forget).toContain("Use the server&#x27;s copy…");
  const note = render({ notChecked: { text: MANIFEST_NOT_CHECKED_TEXT, vaults: [{ id: V, name: "Personal" }], key: "k" } });
  expect(note).toContain("Personal</strong>: This vault isn&#x27;t being checked for missing or restored items.");
  expect(note).toContain("alert-info");
  expect(note).not.toContain("Dismiss");
  expect(others).not.toContain("Use the server");
  expect(others.match(/>Open the web vault</g)).toHaveLength(1);
  // What this browser remembers can't be read: the notice with its way out.
  const memoryHtml = render({ memory: { text: MEMORY_UNREADABLE_TEXT, action: MEMORY_RESET_ACTION, body: MEMORY_RESET_BODY } });
  expect(memoryHtml).toContain("PassAuth can&#x27;t read this device&#x27;s record of your vaults.");
  expect(memoryHtml).toContain("Reset on this device…");
  expect(memoryHtml).not.toContain("Dismiss");
  // ROUND 3 (T1): the list's rows for items that aren't shown (text only, nothing to press).
  const { OtherItems } = await import("../src/popup/vault");
  const rows = renderToStaticMarkup(
    createElement(OtherItems, {
      items: [
        { id: "i1", title: ITEM_LOCKED_TITLE, name: "Mail", vaultName: "Personal" },
        { id: "i2", title: ITEM_LOCKED_TITLE, vaultName: "Team" },
        { id: "i3", title: ITEM_NEWER_TITLE, note: ITEM_NEWER_NOTE, vaultName: "Personal" },
      ],
    }),
  );
  expect(rows).toContain('Item that can&#x27;t be opened</span></span><span class="sub">Mail · Personal<');
  expect(rows).toContain('Item that can&#x27;t be opened</span></span><span class="sub">Team<');
  expect(rows).toContain('Item from a newer version of PassAuth</span></span><span class="sub">Update PassAuth to see this item.<');
  expect(rows).not.toContain("<button");
  const outdated = render({ serverProblem: SERVER_UPDATE_TEXT });
  expect(outdated).toContain("Update your PassAuth server to keep using this app.");
  expect(render({})).toBe("");
});

// ------------------------------------------------------------ review fixes, round 2

/** The server as an admin restores it from a backup: everything as it was then, served as a change. */
const backup = saveServer;
const restoreBackup = restoreServer;
/** Someone with write access uses "Use the server's copy" in the web vault or the desktop app: a new record, one version above the served one. */
function baselineElsewhere() {
  server.revision++;
  server.bump(V);
  server.remanifest(V);
}
/** Open the only account again after signing out (what is remembered stays: the account isn't removed). */
async function signInAgain() {
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionKeys() });
  expect(await vault.ensureUnlocked()).toBe(true);
}

test("ROUND 2 PoC 1 (was: the warning stays for good): the server is restored from a backup and someone writes a new record in the web vault; this browser's warning can be cleared here with 'Use the server's copy', and it writes again", async () => {
  await signedIn();
  const saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  await vault.sync();
  const before = (await memory()).manifests![V]!;
  expect(before.version).toBe(3);
  // The admin restores the server from the backup (honest): items, manifest and log as they were at version 1.
  restoreBackup(saved);
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // An older state that is consistent in itself: acceptable here, by the user's decision only.
  expect(offered()).toStrictEqual(ACCEPT);
  expect(vault.manifestWarning(V)).toBe(MANIFEST_WARNING_TEXT);
  // The owner uses "Use the server's copy" in the web vault: a new record on the restored one, version 2. This
  // browser remembers version 3 of the history that is gone: still a warning (nobody else's action can clear it).
  baselineElsewhere();
  expect(row().manifest_seq).toBe(2);
  await vault.sync();
  expect(warned(), "after the baseline made elsewhere").toStrictEqual([V]);
  expect(offered()).toStrictEqual(ACCEPT);
  await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_HELD_TEXT);
  expect((await memory()).manifests![V], "nothing is accepted without the user").toStrictEqual(before);
  // ROUND 2 (S7): while the warning stands a sync is one delta: no whole fetch, no log.
  let n = server.requests.length;
  server.revision++;
  await vault.sync();
  expect(requestsSince(n), "one sync = one delta").toStrictEqual(["GET /sync"]);
  expect(syncs().at(-1)?.query.since).toBeTruthy();
  // The same after a worker restart: the warning is there from the copy, and nothing is fetched in full.
  n = server.requests.length;
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  expect(
    server.requests
      .slice(n)
      .filter((r) => r.path === "/sync")
      .every((r) => !!r.query.since),
    "no whole fetch after a restart",
  ).toBe(true);
  // Signing out and in again (the only account) keeps the memory, and so the warning, as before.
  await vault.logout();
  await signInAgain();
  await vault.sync();
  expect(warned(), "after signing out and in").toStrictEqual([V]);
  expect(await versions()).toStrictEqual({ [V]: 3 });
  // ROUND 2 (S1): "Use the server's copy" here. One fresh whole fetch, the served copy checked on its own, and this
  // browser's memory replaced by the served manifest, lower than what it remembered. Nothing is sent.
  n = server.requests.length;
  await vault.acceptServerCopy(V);
  expect(
    requestsSince(n).filter((r) => !r.startsWith("GET ")),
    "no request but reads",
  ).toStrictEqual([]);
  expect(
    server.requests.slice(n).filter((r) => r.path === "/sync" && !r.query.since),
    "one fresh whole fetch",
  ).toHaveLength(1);
  expect(warned()).toStrictEqual([]);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 2, link: link(), accepts: 1 } });
  expect(ids()).toStrictEqual(["i1", "i2"]);
  // It writes again, on the accepted record.
  const id = await vault.createItem(login("New"));
  expect(vault.getEntry(id)?.item.name).toBe("New");
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 3, link: link(), accepts: 1 } });
  expect(server.manifestErrors).toStrictEqual([]);
  // The acceptance holds: across a restart (the stored memory was lowered, and stays lowered) and later syncs.
  await reopen();
  server.editElsewhere("i1", { notes: "phone" });
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 4, link: link(), accepts: 1 } });
  // And it is still a memory: the server going back again is a rollback again.
  restoreBackup(saved);
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
});

test("ROUND 2 (S1): restore from a backup, no new record needed: the restored copy itself is acceptable, also for an account that can only read the vault", async () => {
  for (const role of ["owner", "read"] as const) {
    await signedIn({ before: () => (row().role = role) });
    const saved = backup();
    server.editElsewhere("i1", { notes: "new password" });
    server.editElsewhere("i2", { notes: "another" });
    await vault.sync();
    expect(await versions()).toStrictEqual({ [V]: 3 });
    restoreBackup(saved);
    await vault.sync();
    expect(warned(), role).toStrictEqual([V]);
    // Offered to every role: accepting sends nothing and changes nothing for anyone else.
    expect(offered(), role).toStrictEqual(ACCEPT);
    await vault.acceptServerCopy(V);
    expect(warned(), role).toStrictEqual([]);
    expect((await memory()).manifests, role).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 1 } });
    expect(
      server.requests.filter((r) => r.method !== "GET"),
      role,
    ).toStrictEqual([]);
    expect(vault.getEntry("i1")?.item.notes, role).toBe("");
    // A second acceptance later counts on.
    server.editElsewhere("i1", { notes: "after" });
    await vault.sync();
    restoreBackup(saved);
    await vault.sync();
    expect(warned(), role).toStrictEqual([V]);
    await vault.acceptServerCopy(V);
    expect((await memory()).manifests, role).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 2 } });
    expect(warned(), role).toStrictEqual([]);
  }
});

test("ROUND 2 (S1): a served copy that doesn't check out on its own is never accepted here: readers are told who can review it, writers where; nothing is remembered; after a new record made elsewhere it can be", async () => {
  for (const role of ["owner", "read"] as const) {
    await signedIn({ before: () => (row().role = role) });
    const saved = backup();
    server.editElsewhere("i1", { notes: "new password" });
    server.editElsewhere("i2", { notes: "another" });
    await vault.sync();
    const before = (await memory()).manifests;
    // Restored, and an item is missing from the restored state too: the served record doesn't describe the served rows.
    restoreBackup(saved);
    tamper(() => {
      server.items = server.items.filter((i) => i.id !== "i2");
    });
    await vault.sync();
    expect(warned(), role).toStrictEqual([V]);
    const reader = role === "read";
    expect(offered(), role).toStrictEqual(reader ? { text: MANIFEST_WARNING_TEXT, hint: MANIFEST_READER_TEXT } : REVIEW);
    expect(vault.manifestWarning(V), role).toBe(`${MANIFEST_WARNING_TEXT} ${reader ? MANIFEST_READER_TEXT : MANIFEST_REVIEW_TEXT}`);
    await expectReject(vault.acceptServerCopy(V), (e) => e.message === `${MANIFEST_NOT_ACCEPTABLE_TEXT} ${reader ? MANIFEST_READER_TEXT : MANIFEST_REVIEW_TEXT}`);
    expect(warned(), role).toStrictEqual([V]);
    expect((await memory()).manifests, `${role}: nothing accepted`).toStrictEqual(before);
    // The extension writes no record of its own, whatever the role.
    expect(sent("PUT", `/vaults/${V}/manifest`), role).toStrictEqual([]);
    // Someone with write access writes the new record (web vault / desktop app): now it is acceptable, for every role.
    baselineElsewhere();
    await vault.sync();
    expect(warned(), role).toStrictEqual([V]);
    expect(offered(), role).toStrictEqual(ACCEPT);
    await vault.acceptServerCopy(V);
    expect(warned(), role).toStrictEqual([]);
    expect((await memory()).manifests, role).toStrictEqual({ [V]: { version: 2, link: link(), accepts: 1 } });
  }
});

test("ROUND 2 (S1, no manifest served): a backup from before the vault's first manifest is a rollback; accepting forgets what was remembered (the counter stays), writes go on without a manifest, and a first one is started by the ordinary rule", async () => {
  await signedIn({ manifest: false });
  const saved = backup();
  server.startManifestElsewhere(V);
  server.editElsewhere("i1", { notes: "x" });
  await vault.sync();
  expect(await versions()).toStrictEqual({ [V]: 2 });
  restoreBackup(saved);
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // ROUND 3 (T3): accepting "no record" says what it means, under a confirmation of its own…
  expect(offered()).toStrictEqual(FORGET);
  expect(vault.manifestSummary()?.confirm.forgetBody).toBe(
    "Your server no longer shows a record of changes for this vault. If you continue, PassAuth stops checking this vault for missing, restored or out-of-date items until a new record is started.",
  );
  expect(vault.notCheckedSummary()).toBe(null);
  // …and is never done under the ordinary one (the popup sends which text the user confirmed).
  await expectReject(vault.acceptServerCopy(V), (e) => e.message === MANIFEST_CHANGED_TEXT);
  expect(warned()).toStrictEqual([V]);
  expect((await memory()).manifests?.[V]?.version, "nothing was forgotten").toBe(2);
  await vault.acceptServerCopy(V, true);
  expect(warned()).toStrictEqual([]);
  expect((await memory()).manifests, "forgotten, with the acceptance counted and the marker").toStrictEqual({ [V]: { accepts: 1, unchecked: true } });
  // The quiet note, until the vault has a record again.
  const NOTE = { text: MANIFEST_NOT_CHECKED_TEXT, vaults: [{ id: V, name: "Personal" }], key: `["${V}"]` };
  expect(vault.notCheckedSummary()).toStrictEqual(NOTE);
  // The gate is closed (some member's app is too old): written as a vault without a manifest.
  const id = await vault.createItem(login("New"));
  expect(sent("POST", "/items").at(-1)!.body).not.toHaveProperty("manifests");
  expect(vault.getEntry(id)).toBeDefined();
  // A restart doesn't bring the old memory back, and the note is still there (also without the server).
  await reopen(false);
  expect(vault.notCheckedSummary()).toStrictEqual(NOTE);
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([]);
  expect(vault.notCheckedSummary()).toStrictEqual(NOTE);
  // The gate opens: this browser starts the first manifest (nothing is remembered any more), version 1.
  row().manifest_ok = true;
  server.revision++;
  server.bump(V);
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`).map((r) => [r.body.base_seq, r.body.seq])).toStrictEqual([[0, 1]]);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 1 } });
  expect(vault.notCheckedSummary(), "checked again").toBe(null);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 2 PoC 6 (was: the extension locks the vault itself): a vault without a manifest that holds an item this app can't open gets no first manifest from here, and stays usable", async () => {
  await signedIn({
    manifest: false,
    before: () => {
      row().manifest_ok = true;
      Object.assign(serverItem("i1"), { item_key: "not-the-key" });
    },
  });
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`), "no first manifest over the row that doesn't open").toStrictEqual([]);
  expect(row().manifest_seq ?? 0).toBe(0);
  server.revision++;
  await vault.sync();
  await reopen();
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`)).toStrictEqual([]);
  // The item is listed as one that can't be opened (ROUND 3: with the vault's notice), no warning, and the vault takes writes.
  expect([warned(), itemNoticed()]).toStrictEqual([[], [V]]);
  expect(vault.otherItems()).toStrictEqual([{ id: "i1", title: ITEM_LOCKED_TITLE, vaultName: "Personal" }]);
  expect(ids()).toStrictEqual(["i2"]);
  const id = await vault.createItem(login("New"));
  const entry = vault.getEntry(id)!;
  await vault.updateItem(entry, { ...entry.item, notes: "changed" });
  await vault.trashItem(vault.getEntry(id)!);
  expect(sent("POST", "/items").at(-1)!.body).not.toHaveProperty("manifests");
  expect(sent("PUT", `/vaults/${V}/manifest`)).toStrictEqual([]);
  // Once the item is deleted (in the web vault or the desktop app), the first manifest is started as usual.
  server.deleteElsewhere("i1");
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`)).toHaveLength(1);
  expect(row().manifest_seq).toBe(1);
  expect(vault.manifestSummary()).toBe(null);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 2 (S2) + ROUND 3 (T1): a trashed item that came with its data and doesn't open counts like a live one: no first manifest over it; the vault shows the item notice (no warning, writes go on); a trash summary can't be told", async () => {
  const WHOLE = FEATURES.filter((f) => f !== "delta_sync");
  const breakTrashed = () => {
    server.trashElsewhere("i2");
    Object.assign(serverItem("i2"), { item_key: "not-the-key" });
  };
  // A server without delta sync sends the trash whole. No manifest yet: none is started.
  await signedIn({
    manifest: false,
    features: WHOLE,
    before: () => {
      row().manifest_ok = true;
      breakTrashed();
    },
  });
  await vault.sync();
  expect(sent("PUT", `/vaults/${V}/manifest`)).toStrictEqual([]);
  expect([warned(), itemNoticed()]).toStrictEqual([[], [V]]);
  // The trash is never listed.
  expect(vault.otherItems()).toStrictEqual([]);
  await vault.createItem(login("New"));
  // With a manifest (made by another app): the record checks out, the trashed item doesn't open: the notice, and
  // the vault takes writes.
  await signedIn({ features: WHOLE, before: breakTrashed });
  expect([warned(), itemNoticed()]).toStrictEqual([[], [V]]);
  expect(offered()).toStrictEqual(ITEM);
  expect(ids(), "the vault stays readable").toStrictEqual(["i1"]);
  await vault.createItem(login("New"));
  // Deleted for good elsewhere: the notice goes by itself.
  server.deleteElsewhere("i2");
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  await vault.createItem(login("New"));
  expect(server.manifestErrors).toStrictEqual([]);
  // A reader gets the notice alone.
  await signedIn({
    features: WHOLE,
    before: () => {
      breakTrashed();
      row().role = "read";
    },
  });
  expect(offered()).toStrictEqual({ text: MANIFEST_ITEM_TEXT });
  // With delta sync the trash comes as summaries (no key, no data): nothing to open, so nothing to tell from here.
  await signedIn({ before: breakTrashed });
  expect(vault.manifestSummary()).toBe(null);
});

test("ROUND 2 (S2) + ROUND 3 (T1): after 'Use the server's copy' a vault that still holds an item that doesn't open shows the item notice (at once, and while the row remains) and takes writes; no first manifest is started over such a row", async () => {
  await signedIn();
  const saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  server.editElsewhere("i2", { notes: "another" });
  await vault.sync();
  // Restored from a backup, and one item's key is broken there (the record doesn't cover item keys).
  restoreBackup(saved);
  Object.assign(serverItem("i1"), { item_key: "not-the-key" });
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // The record itself is out of date: that can be accepted (one line per vault: the warning comes first)…
  expect(offered()).toStrictEqual(ACCEPT);
  await vault.acceptServerCopy(V);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 1 } });
  // …and the item notice is there at once (not only after the next sync), and across a restart. The row carries the
  // name of the copy this browser had.
  expect([warned(), itemNoticed()]).toStrictEqual([[], [V]]);
  expect(offered()).toStrictEqual(ITEM);
  expect(vault.otherItems()).toStrictEqual([{ id: "i1", title: ITEM_LOCKED_TITLE, name: "Item 1", vaultName: "Personal" }]);
  await reopen(false);
  expect(offered()).toStrictEqual(ITEM);
  await reopen();
  await vault.sync();
  expect(offered()).toStrictEqual(ITEM);
  expect(server.requests.filter((r) => r.method !== "GET")).toStrictEqual([]);
  // Nothing is held for it.
  await vault.createItem(login("Meanwhile"));
  // Deleted in the web vault (an ordinary write with the vault's next manifest): the notice goes.
  server.deleteElsewhere("i1");
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  expect(vault.otherItems()).toStrictEqual([]);
  await vault.createItem(login("New"));
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 2 (S4): what this browser remembers can't be read (damaged, or written by a later version): vaults with a manifest are unchecked, vaults without one stay writable, nothing is overwritten; after three failed reads and a whole sync 'Reset on this device' is offered and works", async () => {
  for (const garbage of ["garbage", { v: 2, manifests: { [V]: { version: 9, link: "a".repeat(43) } } }]) {
    // A vault without a manifest: written as always while the record can't be read.
    await signedIn({ manifest: false });
    await vault.lockAll();
    await storage.deviceMemory.update("https://vault.test", "u-1", () => garbage);
    await reopen();
    await vault.sync();
    expect(warned()).toStrictEqual([]);
    const plain = await vault.createItem(login("Plain"));
    expect(vault.getEntry(plain)).toBeDefined();
    expect(await storage.deviceMemory.read("https://vault.test", "u-1"), "never overwritten").toStrictEqual(garbage);

    // A vault with a manifest.
    await signedIn();
    await vault.lockAll();
    await storage.deviceMemory.update("https://vault.test", "u-1", () => garbage);
    await reopen();
    // Unchecked: no warning, the items are shown, and nothing is written into it.
    expect(warned()).toStrictEqual([]);
    expect(ids()).toStrictEqual(["i1", "i2"]);
    await expectReject(vault.createItem(login("New")), (e) => e.message === MANIFEST_UNCHECKED_TEXT || e.message === MEMORY_UNREADABLE_TEXT);
    // Nothing shows a warning, so there is nothing to accept (and nothing is written over the record).
    await vault.acceptServerCopy(V);
    for (let n = 0; n < 3; n++) {
      server.revision++;
      await vault.sync();
    }
    // Three failed reads with a whole sync among them: the way out is offered, and writes say why they are held.
    expect(vault.memoryNotice()).toStrictEqual({ text: MEMORY_UNREADABLE_TEXT, action: MEMORY_RESET_ACTION, body: MEMORY_RESET_BODY });
    expect(syncs().some((r) => !r.query.since)).toBe(true);
    await expectReject(vault.createItem(login("New")), (e) => e.message === MEMORY_UNREADABLE_TEXT);
    expect(sent("POST", "/items")).toStrictEqual([]);
    expect(await storage.deviceMemory.read("https://vault.test", "u-1"), "never overwritten").toStrictEqual(garbage);
    // A worker restart in this state doesn't fetch everything again (the count is kept across restarts).
    let n = syncs().length;
    await reopen();
    await vault.sync();
    expect(vault.memoryNotice()).not.toBe(null);
    expect(
      syncs()
        .slice(n)
        .every((r) => !!r.query.since),
      "only deltas",
    ).toBe(true);
    // "Reset on this device": the record is put aside, the server's copy is trusted as it is now (one whole sync),
    // and a new record starts.
    n = syncs().length;
    await vault.resetDeviceMemory();
    expect(
      syncs()
        .slice(n)
        .filter((r) => !r.query.since),
    ).toHaveLength(1);
    expect(vault.memoryNotice()).toBe(null);
    expect(warned()).toStrictEqual([]);
    expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link() } });
    expect(await asideRecord(), "kept aside, not thrown away").toStrictEqual(garbage);
    const id = await vault.createItem(login("New"));
    expect(vault.getEntry(id)).toBeDefined();
    expect(server.manifestErrors).toStrictEqual([]);
    // From here on it is an ordinary memory: a restart reads it, and nothing is offered.
    await reopen();
    await vault.sync();
    expect(vault.memoryNotice()).toBe(null);
    expect(await versions()).toStrictEqual({ [V]: 2 });
    // Nothing to reset when the record reads.
    await vault.resetDeviceMemory();
    expect(await versions()).toStrictEqual({ [V]: 2 });
  }
});

test("ROUND 2 (S4): a record that reads again before the reset is used as it is: the count starts over, nothing is offered, nothing is put aside", async () => {
  await signedIn();
  const good = await storage.deviceMemory.read("https://vault.test", "u-1");
  await vault.lockAll();
  await storage.deviceMemory.update("https://vault.test", "u-1", () => "garbage");
  await reopen();
  expect(vault.memoryNotice(), "not after one or two tries").toBe(null);
  await vault.lockAll();
  await storage.deviceMemory.update("https://vault.test", "u-1", () => good);
  await reopen();
  await vault.sync();
  expect(vault.memoryNotice()).toBe(null);
  expect(warned()).toStrictEqual([]);
  await vault.createItem(login("New"));
  expect(await asideRecord()).toBeUndefined();
  // Unreadable again later: the earlier failures don't count.
  await vault.lockAll();
  await storage.deviceMemory.update("https://vault.test", "u-1", () => "garbage");
  await reopen();
  expect(vault.memoryNotice()).toBe(null);
});

test("ROUND 2 (S5): old trash goes by the strict rule (deleted_at < server_time - period) and never before this browser watched it in the trash for max(period, 7) days, whatever period the server names", async () => {
  const now = 1_800_000_000;
  at(now);
  await signedIn({ items: 3 });
  server.now = now;
  // A one-day setting (an admin's choice, or a server's lie): the floor is a week by this browser's own clock.
  server.trashDays = 1;
  server.trashElsewhere("i1", now - 400 * DAY);
  await vault.sync();
  expect((await memory()).trashSeen).toStrictEqual({ i1: now });
  const purges = () => sent("POST", `/vaults/${V}/trash/purge`);
  for (const days of [1, 2, 6]) {
    at(now + days * DAY);
    server.now = now + days * DAY;
    server.revision++;
    await vault.sync();
    expect(purges(), `${days} days`).toHaveLength(0);
  }
  at(now + 7 * DAY - 1);
  server.now = now + 7 * DAY - 1;
  server.revision++;
  await vault.sync();
  expect(purges(), "a second short of a week").toHaveLength(0);
  at(now + 7 * DAY);
  server.now = now + 7 * DAY;
  server.revision++;
  await vault.sync();
  expect(purges().map((r) => r.body.items.map((i: { id: string }) => i.id))).toStrictEqual([["i1"]]);
  // The strict edge: trashed exactly `period` ago by the server's clock is not due yet; a second later it is.
  const later = now + 100 * DAY;
  server.trashDays = 30;
  at(later);
  server.now = later;
  server.trashElsewhere("i2", later);
  await vault.sync();
  expect((await memory()).trashSeen).toStrictEqual({ i2: later });
  at(later + 30 * DAY);
  server.now = later + 30 * DAY;
  server.revision++;
  await vault.sync();
  expect(purges(), "deleted_at == server_time - period").toHaveLength(1);
  at(later + 30 * DAY + 1);
  server.now = later + 30 * DAY + 1;
  server.revision++;
  await vault.sync();
  expect(purges().map((r) => r.body.items.map((i: { id: string }) => i.id))).toStrictEqual([["i1"], ["i2"]]);
  expect(server.manifestErrors).toStrictEqual([]);
});

// ------------------------------------------------------------ review fixes, round 3 (final)

test("ROUND 3 PoC 3 (T2; was: every answer dropped unseen): a real restore from a backup (the server's sync revision goes back with everything else) is judged: the warning comes, 'Use the server's copy' works, and writes go through again", async () => {
  await signedIn();
  const saved = backup();
  const savedRevision = server.revision;
  server.editElsewhere("i1", { notes: "new password" });
  server.addElsewhere("i3", V, JSON.stringify(login("Item 3")));
  await vault.sync();
  expect((await memory()).manifests![V]!.version).toBe(3);
  // The admin restores the backup: items, manifests, logs AND the account's revision are yesterday's.
  restoreBackup(saved);
  expect(server.revision).toBe(savedRevision);
  const before = server.requests.length;
  await vault.sync();
  // The delta from a server whose revision went back isn't used; one whole answer is, and it is judged.
  expect(requestsSince(before)).toStrictEqual(["GET /sync", "GET /sync"]);
  expect(syncs().at(-1)?.query.since).toBeUndefined();
  expect(warned()).toStrictEqual([V]);
  expect(offered()).toStrictEqual(ACCEPT);
  await expectReject(vault.createItem(login("Held")), (e) => e.message === MANIFEST_HELD_TEXT);
  // The warning stands without a whole fetch at every sync, and the answers are no longer "older than what is shown".
  const quiet = server.requests.length;
  await vault.sync();
  expect(requestsSince(quiet)).toStrictEqual(["GET /sync"]);
  expect(warned()).toStrictEqual([V]);
  await vault.acceptServerCopy(V);
  expect(vault.manifestSummary()).toBe(null);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 1 } });
  expect(ids()).toStrictEqual(["i1", "i2"]);
  const id = await vault.createItem(login("New"));
  expect(vault.getEntry(id)).toBeDefined();
  expect(server.revision).toBeGreaterThan(savedRevision);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 3 (T2): the same after a worker restart (the offline copy carries the newer revision), on a server without delta sync, and for the popup's revision check; an unchanged vault raises nothing", async () => {
  // A restart between the restore and the first sync.
  await signedIn();
  let saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  await vault.sync();
  restoreBackup(saved);
  await reopen();
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  await vault.acceptServerCopy(V);
  await vault.createItem(login("New"));
  // Found by the cheap revision check the popup runs when it opens (a lower revision is a difference too).
  await signedIn();
  saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  await vault.sync();
  restoreBackup(saved);
  await vault.refreshIfStale();
  expect(warned()).toStrictEqual([V]);
  // A server without delta sync (every answer is whole): judged at once.
  await signedIn({ features: FEATURES.filter((f) => f !== "delta_sync") });
  saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  await vault.sync();
  restoreBackup(saved);
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  await vault.refreshIfStale();
  expect(warned()).toStrictEqual([V]);
  // Restored to a state in which the vault is what this browser last saw (only the revision is lower): no warning.
  await signedIn();
  saved = backup();
  server.revision += 5;
  await vault.sync();
  restoreBackup(saved);
  await vault.sync();
  expect(vault.manifestSummary()).toBe(null);
  await vault.createItem(login("New"));
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 3 (T4): 'Use the server's copy' also drops the vault's item marks: the newer copies this browser kept, the 'older version' marks and the counters of items the server no longer lists, for that vault only; no 'older versions' notice remains", async () => {
  const OTHER = "v-team";
  await signedIn({
    before: () => {
      server.vaults.push({ id: OTHER, wrapped_key: "team-1", key_kind: "sealed", role: "write", meta: JSON.stringify({ name: "Team" }), key_epoch: 1 });
      server.addElsewhere("t1", OTHER, JSON.stringify({ ...login("Team item"), rev: 1 }));
    },
  });
  const saved = backup();
  // Since the backup: both items of the vault edited (their counters go up), one added; one edited in the other vault.
  server.editElsewhere("i1", { notes: "new password", rev: 5 });
  server.editElsewhere("i2", { notes: "newer", rev: 3 });
  server.addElsewhere("i3", V, JSON.stringify({ ...login("Item 3"), rev: 1 }));
  server.editElsewhere("t1", { notes: "team newer", rev: 4 });
  await vault.sync();
  expect((await memory()).itemRevs).toStrictEqual({ i1: 5, i2: 3, i3: 1, t1: 4 });
  // The admin restores the backup.
  restoreBackup(saved);
  await vault.sync();
  expect(warned()).toStrictEqual([V]);
  // This browser kept its newer copies and marked them; the item the server no longer lists is kept aside.
  expect(["i1", "i2", "t1"].map((id) => [vault.rolledBack(id), vault.getEntry(id)?.item.notes])).toStrictEqual([
    [true, "new password"],
    [true, "newer"],
    [true, "team newer"],
  ]);
  expect(vault.rollbackSummary()).not.toBe(null);
  expect(Object.keys((await stored())?.served ?? {}).sort()).toStrictEqual(["i1", "i2", "t1"]);
  expect((await stored())?.stash?.map((r) => r.id)).toStrictEqual(["i3"]);
  await vault.acceptServerCopy(V);
  expect(vault.manifestSummary()).toBe(null);
  // The accepted vault: the server's rows are shown and stored, unmarked; counters are the served ones; i3 is forgotten.
  expect(["i1", "i2"].map((id) => [vault.rolledBack(id), vault.getEntry(id)?.item.notes])).toStrictEqual([
    [false, ""],
    [false, ""],
  ]);
  for (const id of ["i1", "i2"]) expect(await storedItem(id)).toMatchObject({ item_key: serverItem(id).item_key, data: serverItem(id).data });
  expect((await stored())?.stash).toBeUndefined();
  // The other vault (no record, not accepted): its kept copy and its mark stay, and so does the notice, for it alone.
  expect([vault.rolledBack("t1"), vault.getEntry("t1")?.item.notes]).toStrictEqual([true, "team newer"]);
  expect(Object.keys((await stored())?.served ?? {})).toStrictEqual(["t1"]);
  const mem = (await memory()) as { itemRevs?: Record<string, number>; rolledBack?: Record<string, string> };
  expect(mem.itemRevs).toStrictEqual({ t1: 4, i1: 0, i2: 0 });
  expect(mem.rolledBack).toStrictEqual({ t1: "kept" });
  expect(JSON.parse(vault.rollbackSummary()!.key)).toStrictEqual([["t1", "kept"]]);
  // It stays so: after a sync, a restart, and an edit made from the accepted copy.
  await vault.sync();
  await reopen();
  await vault.sync();
  expect(["i1", "i2"].map((id) => vault.rolledBack(id))).toStrictEqual([false, false]);
  const entry = vault.getEntry("i1")!;
  await vault.updateItem(entry, { ...entry.item, notes: "after the restore" });
  expect(JSON.parse(serverItem("i1").data)).toMatchObject({ notes: "after the restore", rev: 1 });
  expect(vault.manifestSummary()).toBe(null);
  expect(server.manifestErrors).toStrictEqual([]);
});

test("ROUND 3 (T4): the marks go only with an acceptance: a refused one (the served copy can't be accepted) leaves the kept copies, the marks and the counters as they were", async () => {
  await signedIn();
  const saved = backup();
  server.editElsewhere("i1", { notes: "new password", rev: 5 });
  await vault.sync();
  restoreBackup(saved);
  // Restored, and an item is missing from the restored state too: nothing to accept here.
  server.items = server.items.filter((i) => i.id !== "i2");
  await vault.sync();
  expect(offered()).toStrictEqual(REVIEW);
  await expectReject(vault.acceptServerCopy(V), (e) => e.message === `${MANIFEST_NOT_ACCEPTABLE_TEXT} ${MANIFEST_REVIEW_TEXT}`);
  expect([vault.rolledBack("i1"), vault.getEntry("i1")?.item.notes]).toStrictEqual([true, "new password"]);
  expect(((await memory()) as { itemRevs?: Record<string, number> }).itemRevs).toMatchObject({ i1: 5 });
  expect(Object.keys((await stored())?.served ?? {})).toStrictEqual(["i1"]);
});

test("ROUND 3 (finding 4): the copy changes while the acceptance is being stored (a sync took another answer over): its verdict is not overwritten with 'ok'; the states are left and a sync decides", async () => {
  await signedIn();
  const saved = backup();
  server.editElsewhere("i1", { notes: "new password" });
  await vault.sync();
  restoreBackup(saved);
  await vault.sync();
  expect(offered()).toStrictEqual(ACCEPT);
  // The second write of the memory record from here on is the acceptance's own (the first: the fresh fetch's copy).
  // Before it is stored, the server hides an item (no record of that) and a sync takes that answer over.
  const update = storage.deviceMemory.update.bind(storage.deviceMemory);
  let calls = 0;
  const spy = vi.spyOn(storage.deviceMemory, "update").mockImplementation(async (server_, user, fn) => {
    if (++calls === 2) {
      tamper(() => {
        server.tombstones.push({ id: "i2", vault_id: V, seq: (row().seq ?? 0) + 1 });
        server.items = server.items.filter((i) => i.id !== "i2");
      });
      await vault.sync();
      expect(ids(), "the other answer is shown").toStrictEqual(["i1"]);
    }
    return update(server_, user, fn);
  });
  await expectReject(vault.acceptServerCopy(V), (e) => e.message === MANIFEST_CHANGED_TEXT);
  spy.mockRestore();
  expect(calls).toBeGreaterThanOrEqual(2);
  // The vault still shows its warning (for the copy shown now, which can't be accepted here), and takes no writes.
  expect(warned()).toStrictEqual([V]);
  expect(offered()).toStrictEqual(REVIEW);
  await expectReject(vault.createItem(login("Held")), (e) => e.message === MANIFEST_HELD_TEXT);
  await reopen(false);
  expect(warned()).toStrictEqual([V]);
});

test("ROUND 3 (T3): the confirmation given must be the one the fresh answer needs: 'no record' was confirmed, but the server shows a record again: nothing is accepted until the user confirms what is shown now", async () => {
  await signedIn({ manifest: false });
  const none = backup();
  server.startManifestElsewhere(V);
  const first = backup();
  await vault.sync();
  server.editElsewhere("i1", { notes: "x" });
  await vault.sync();
  expect(await versions()).toStrictEqual({ [V]: 2 });
  restoreBackup(none);
  await vault.sync();
  expect(offered()).toStrictEqual(FORGET);
  // Between the popup's notice and the confirmation the server shows another state: its first record again.
  restoreBackup(first);
  await expectReject(vault.acceptServerCopy(V, true), (e) => e.message === MANIFEST_CHANGED_TEXT);
  expect((await memory()).manifests?.[V]).toStrictEqual({ version: 2, link: expect.any(String) });
  expect(vault.notCheckedSummary()).toBe(null);
  // The popup now shows the vault as that answer has it, with the ordinary confirmation, which then works.
  expect(offered()).toStrictEqual(ACCEPT);
  await vault.acceptServerCopy(V);
  expect((await memory()).manifests).toStrictEqual({ [V]: { version: 1, link: link(), accepts: 1 } });
  expect([vault.manifestSummary(), vault.notCheckedSummary()]).toStrictEqual([null, null]);
});
