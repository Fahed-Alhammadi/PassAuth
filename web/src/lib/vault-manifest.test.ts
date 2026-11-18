/**
 * Vault manifests through `vault.ts` against a fake server that keeps manifests like the real one (real core): every
 * write carries the vault's next manifest, own writes are shown without asking only when the answer agrees, conflicts
 * are retried at most three times, every sync answer is checked (warning, writes held back, device memory), a first
 * manifest is started when the server says every app is ready, "Use the server's copy" writes a new baseline, and due
 * trash is deleted by the app. Vaults without a manifest get exactly the requests from before.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import { loadCore, signedVectors, unb64, vectorAccounts, type SignedVectors } from "./test-core";

type Opts = { method?: string; body?: unknown };
const h = vi.hoisted(() => ({
  handler: null as null | ((path: string, opts: Opts) => Promise<unknown>),
  config: { features: [] as string[], limits: {} as Record<string, number> } as { features: string[]; limits?: Record<string, number> } | null,
}));

vi.mock("./api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("./api")>();
  return {
    ...orig,
    api: (path: string, opts?: Opts) => h.handler!(path, opts ?? {}),
    getTokens: () => ({ access: "access", refresh: "refresh" }),
    setTokens: () => {},
    knownPublicConfig: () => h.config,
    loadPublicConfig: async () => h.config,
    refreshPublicConfig: async () => h.config,
  };
});

class FakeSocket {
  onopen: unknown = null;
  onmessage: unknown = null;
  onclose: unknown = null;
  close() {}
}
const storage = new Map<string, string>();
vi.stubGlobal("WebSocket", FakeSocket);
vi.stubGlobal("location", new URL("https://vault.example.test/"));
vi.stubGlobal("localStorage", {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => void storage.set(k, v),
  removeItem: (k: string) => void storage.delete(k),
});

import { ApiError } from "./api";
import { MANIFEST_BUSY, MANIFEST_HELD, MANIFEST_NOT_READY, manifestsKey } from "./manifest";
import { emptyItem, type Item } from "./types";
import {
  acceptServerCopy,
  boot,
  createItem,
  getState,
  importItems,
  lock,
  purgeItem,
  restoreItem,
  restoreItemVersion,
  restoreUnlocked,
  rotateVaultKey,
  sync as syncNow,
  trashItem,
  updateItem,
} from "./vault";

let v: SignedVectors;
let alice: { id: string; account: core.Account; record: core.IdentityRecord };
const FEATURES = ["delta_sync", "signed_sharing", "key_epoch", "vault_manifest"];
const DAY = 86400;

beforeAll(async () => {
  await loadCore();
  v = await signedVectors();
  alice = vectorAccounts(v).get("alice")!;
  vi.spyOn(core.Account.prototype, "matchesBundle").mockImplementation(function (this: core.Account, b: unknown) {
    return (b as { account_id?: unknown } | null)?.account_id === (this.legacyIdentity() as { user_id: string }).user_id;
  });
});
afterAll(() => vi.unstubAllGlobals());

// ------------------------------------------------------------- fake server

interface ItemRow {
  id: string;
  vault_id: string;
  item_key: string;
  data: string;
  revision: number;
  deleted_at: number | null;
  created_at: number;
  updated_at: number;
  /** The server's clock at the row's last write (delta sync). */
  at: number;
}
interface VaultState {
  id: string;
  meta: string;
  wrapped: string;
  epoch: number;
  seq: number;
  role: string;
  manifest: string | null;
  manifestSeq: number;
  manifestOk: boolean;
}
interface Entry {
  vault_id: string;
  seq: number;
  sealed: string;
}
interface World {
  revision: number;
  clock: number;
  vaults: Map<string, VaultState>;
  items: Map<string, ItemRow>;
  tombs: { id: string; vault_id: string; at: number }[];
  pins: { key_pins: string | null; seq: number };
  calls: { method: string; path: string; body: unknown }[];
  /** Run before the next request whose path starts with `path` (once): another device's write, or an error to throw. */
  next: { path: string; method?: string; run: () => void }[];
  serverTime: number;
  trashDays: number;
  /** Rows the next delta answer sends without their data. */
  bare: Set<string>;
}
let w: World;
const A = () => v.vault.id;
const B = "00000000-0000-4000-8000-0000000000b2";

const err = (status: number, code: string) => new ApiError(status, code, code, undefined, undefined, { error: code });
const keyOf = (vault: VaultState) => alice.account.openVaultKey(vault.id, vault.wrapped, "account", vault.epoch, true);
const rowsOf = (vaultId: string) => [...w.items.values()].filter((r) => r.vault_id === vaultId);
const withKey = <T>(vaultId: string, fn: (key: core.VaultKey, vault: VaultState) => T): T => {
  const vault = w.vaults.get(vaultId)!;
  const key = keyOf(vault);
  try {
    return fn(key, vault);
  } finally {
    key.free();
  }
};

/** The fake server's vault checked the way an app checks it (no device memory). */
const serverCheck = (vaultId: string) =>
  withKey(vaultId, (key, vault) => key.manifestVerify(vaultId, vault.epoch, vault.manifestSeq, vault.manifest, null, rowsOf(vaultId)) as { status: string; version: number; live: number; trashed: number });

function bump(vaultId: string): number {
  w.clock++;
  w.revision++;
  const vault = w.vaults.get(vaultId)!;
  vault.seq++;
  return vault.seq;
}

/** The real server's rule: a vault with a manifest needs its next one; a manifest for a vault without one is refused. */
function checkManifests(affected: string[], sent: Entry[]) {
  for (const m of sent) {
    const vault = w.vaults.get(m.vault_id);
    if (!vault || !affected.includes(m.vault_id)) throw err(400, "bad_request");
    if (vault.manifestSeq === 0 || m.seq !== vault.manifestSeq + 1) throw err(409, "manifest_conflict");
  }
  for (const id of affected) if (w.vaults.get(id)!.manifestSeq > 0 && !sent.some((m) => m.vault_id === id)) throw err(400, "manifest_required");
}
function storeManifests(sent: Entry[]) {
  for (const m of sent) Object.assign(w.vaults.get(m.vault_id)!, { manifest: m.sealed, manifestSeq: m.seq });
}
const entriesOf = (b: Record<string, unknown>): Entry[] => (Array.isArray(b.manifests) ? (b.manifests as Entry[]) : []);
function queryOf(path: string, vaultId: string): { path: string; revision?: number; sent: Entry[] } {
  const [bare, query = ""] = path.split("?");
  const q = new URLSearchParams(query);
  const seq = q.get("manifest_seq");
  const sealed = q.get("manifest");
  if ((seq === null) !== (sealed === null)) throw err(400, "bad_request");
  return { path: bare, ...(q.has("revision") ? { revision: Number(q.get("revision")) } : {}), sent: seq !== null ? [{ vault_id: vaultId, seq: Number(seq), sealed: sealed! }] : [] };
}

function syncAnswer(since: number | null) {
  const bare = w.bare;
  w.bare = new Set();
  const strip = (r: ItemRow) => {
    const { at: _at, ...row } = r;
    if (!bare.has(r.id)) return row;
    const { data: _data, ...rest } = row;
    return rest;
  };
  return {
    revision: w.revision,
    cursor: `c${w.clock}`,
    user: { id: alice.id, email: "alice@example.com", name: "Alice", email_verified: true, identity: alice.record, key_pins_seq: w.pins.seq },
    bundle: { account_id: alice.id },
    vaults: [...w.vaults.values()].map((x) => ({
      id: x.id,
      meta: x.meta,
      role: x.role,
      wrapped_key: x.wrapped,
      key_kind: "account",
      rotation_pending: 0,
      key_epoch: x.epoch,
      seq: x.seq,
      member_roster: null,
      member_roster_seq: 0,
      share: null,
      manifest: x.manifest,
      manifest_seq: x.manifestSeq,
      manifest_ok: x.manifestSeq > 0 || x.manifestOk,
    })),
    items: [...w.items.values()].filter((r) => since === null || r.at > since).map(strip),
    invitations: [],
    server_time: w.serverTime,
    trash_days: w.trashDays,
    ...(since === null ? {} : { delta: true, deleted: w.tombs.filter((t) => t.at > since).map(({ id, vault_id }) => ({ id, vault_id })), reset: [] }),
  };
}

async function handle(path: string, opts: Opts): Promise<unknown> {
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  w.calls.push({ method, path, body: opts.body });
  const i = w.next.findIndex((n) => path.startsWith(n.path) && (!n.method || n.method === method));
  if (i >= 0) w.next.splice(i, 1)[0].run();
  const b = (opts.body ?? {}) as Record<string, unknown>;
  if (path === "/sync") return syncAnswer(null);
  if (path.startsWith("/sync?since=")) return syncAnswer(Number(decodeURIComponent(path.split("=")[1]).slice(1)));
  if (path === "/sync/revision") return { revision: w.revision };
  if (path === "/account") return {};
  if (path === "/account/identity") return { ok: true, created: false };
  if (path === "/account/key-pins") {
    if (method === "GET") return w.pins;
    if (b.seq !== w.pins.seq + 1) throw err(409, "key_pins_changed");
    w.pins = { key_pins: b.key_pins as string, seq: b.seq as number };
    w.revision++;
    return { seq: b.seq };
  }
  const members = /^\/vaults\/([^/]+)\/members$/.exec(path);
  if (members && method === "GET") {
    const id = v.identities.find((x) => x.name === "alice")!.publicIdentity;
    return {
      members: [{ ...id, signing_key: alice.record.signing_key, identity_signature: alice.record.identity_signature, x25519_signature: alice.record.x25519_signature, email: "alice@example.com", name: "Alice", role: "owner", status: "active", key_kind: "account", share: null }],
      key_epoch: w.vaults.get(members[1])!.epoch,
      member_roster: null,
      member_roster_seq: 0,
    };
  }
  if (/^\/vaults\/[^/]+\/rosters\?after=/.test(path)) return { rosters: [], latest: 0, more: false };

  if (path === "/items" && method === "POST") {
    const vaultId = b.vault_id as string;
    const vault = w.vaults.get(vaultId)!;
    if (b.key_epoch !== vault.epoch) throw err(409, "vault_key_changed");
    const have = w.items.get(b.id as string);
    if (have) {
      if (have.data !== b.data || have.item_key !== b.key) throw err(409, "item_exists");
      return { revision: have.revision, vault_seq: vault.seq, manifest_seq: vault.manifestSeq };
    }
    checkManifests([vaultId], entriesOf(b));
    const seq = bump(vaultId);
    storeManifests(entriesOf(b));
    w.items.set(b.id as string, { id: b.id as string, vault_id: vaultId, item_key: b.key as string, data: b.data as string, revision: w.clock * 1000, deleted_at: null, created_at: 1, updated_at: 1, at: w.clock });
    return { revision: w.clock * 1000, vault_seq: seq, manifest_seq: vault.manifestSeq };
  }
  if (path === "/items/import") {
    const items = b.items as { id: string; vault_id: string; key: string; data: string }[];
    const vaultId = items[0].vault_id;
    const vault = w.vaults.get(vaultId)!;
    const stored = items.filter((it) => w.items.has(it.id));
    if (stored.length === items.length && stored.every((it) => w.items.get(it.id)!.data === it.data)) return { imported: items.length, vault_seqs: { [vaultId]: vault.seq }, manifest_seqs: { [vaultId]: vault.manifestSeq }, vault_seq: vault.seq, manifest_seq: vault.manifestSeq };
    if (stored.length) throw err(409, "item_exists");
    checkManifests([vaultId], entriesOf(b));
    const seq = bump(vaultId);
    storeManifests(entriesOf(b));
    for (const it of items) w.items.set(it.id, { id: it.id, vault_id: vaultId, item_key: it.key, data: it.data, revision: w.clock * 1000, deleted_at: null, created_at: 1, updated_at: 1, at: w.clock });
    return { imported: items.length, vault_seqs: { [vaultId]: seq }, manifest_seqs: { [vaultId]: vault.manifestSeq }, vault_seq: seq, manifest_seq: vault.manifestSeq };
  }
  const put = /^\/items\/([^/?]+)$/.exec(path);
  if (put && method === "PUT") {
    const have = w.items.get(put[1]);
    if (!have) throw err(404, "not_found");
    const to = b.vault_id as string;
    if (b.key_epoch !== w.vaults.get(to)!.epoch) throw err(409, "vault_key_changed");
    if (b.revision !== have.revision) throw err(409, "revision_conflict");
    const affected = [...new Set([have.vault_id, to])];
    checkManifests(affected, entriesOf(b));
    for (const id of affected) bump(id);
    storeManifests(entriesOf(b));
    if (have.vault_id !== to) w.tombs.push({ id: have.id, vault_id: have.vault_id, at: w.clock });
    w.items.set(have.id, { ...have, vault_id: to, item_key: b.key as string, data: b.data as string, revision: w.clock * 1000, at: w.clock });
    return { revision: w.clock * 1000, vault_seq: w.vaults.get(to)!.seq, manifest_seq: w.vaults.get(to)!.manifestSeq };
  }
  const state = /^\/items\/([^/?]+)(\/restore|\/permanent)?(\?.*)?$/.exec(path);
  if (state && ((method === "DELETE" && state[2] !== "/restore") || (method === "POST" && state[2] === "/restore"))) {
    const have = w.items.get(state[1]);
    if (!have) throw err(404, "not_found");
    const q = queryOf(path, have.vault_id);
    if (q.revision !== undefined && q.revision !== have.revision) throw err(409, "revision_conflict");
    checkManifests([have.vault_id], q.sent);
    const seq = bump(have.vault_id);
    storeManifests(q.sent);
    if (state[2] === "/permanent") {
      w.items.delete(have.id);
      w.tombs.push({ id: have.id, vault_id: have.vault_id, at: w.clock });
    } else w.items.set(have.id, { ...have, deleted_at: state[2] === "/restore" ? null : w.serverTime, revision: w.clock * 1000, at: w.clock });
    return { revision: w.clock * 1000, vault_seq: seq, manifest_seq: w.vaults.get(have.vault_id)!.manifestSeq };
  }
  const purge = /^\/vaults\/([^/]+)\/trash\/purge$/.exec(path);
  if (purge) {
    const items = b.items as { id: string; revision?: number }[];
    for (const it of items) {
      const have = w.items.get(it.id);
      if (!have || have.vault_id !== purge[1] || have.deleted_at === null || (it.revision !== undefined && it.revision !== have.revision)) throw err(409, "revision_conflict");
    }
    checkManifests([purge[1]], entriesOf(b));
    const seq = bump(purge[1]);
    storeManifests(entriesOf(b));
    for (const it of items) {
      w.items.delete(it.id);
      w.tombs.push({ id: it.id, vault_id: purge[1], at: w.clock });
    }
    return { purged: items.length, revision: w.revision, vault_seq: seq, manifest_seq: w.vaults.get(purge[1])!.manifestSeq };
  }
  const manifest = /^\/vaults\/([^/]+)\/manifest$/.exec(path);
  if (manifest && method === "PUT") {
    const vault = w.vaults.get(manifest[1])!;
    if (vault.role === "read") throw err(403, "forbidden");
    if (vault.manifestSeq !== b.base_seq || vault.seq !== b.vault_seq || !((b.seq as number) > (b.base_seq as number))) throw err(409, "manifest_conflict");
    if (vault.manifestSeq === 0 && !vault.manifestOk) throw err(409, "manifest_not_ready");
    const seq = bump(vault.id);
    Object.assign(vault, { manifest: b.sealed, manifestSeq: b.seq });
    return { revision: w.revision, vault_seq: seq, manifest_seq: vault.manifestSeq };
  }
  const rotate = /^\/vaults\/([^/]+)\/rotate$/.exec(path);
  if (rotate) {
    const vault = w.vaults.get(rotate[1])!;
    if (b.key_epoch !== vault.epoch) throw err(409, "vault_key_changed");
    const items = b.items as { id: string; key: string; data: string; revision?: number }[];
    for (const it of items) if (it.revision !== undefined && it.revision !== w.items.get(it.id)?.revision) throw err(409, "revision_conflict");
    checkManifests([vault.id], entriesOf(b));
    const seq = bump(vault.id);
    storeManifests(entriesOf(b));
    for (const it of items) w.items.set(it.id, { ...w.items.get(it.id)!, item_key: it.key, data: it.data, revision: w.clock * 1000, at: w.clock });
    vault.wrapped = (b.keys as { wrapped_key: string }[])[0].wrapped_key;
    if (typeof b.meta === "string") vault.meta = b.meta;
    vault.epoch++;
    return { revision: w.revision, key_epoch: vault.epoch, vault_seq: seq, manifest_seq: vault.manifestSeq };
  }
  throw new ApiError(404, "not_found", `no route ${method} ${path}`);
}

// ------------------------------------------------- another device (and tampering)

const login = (name: string): Item => ({ ...emptyItem("login"), name, created_at: 1, updated_at: 1 });

/** Another device of the account adds an item the right way (its manifest included when the vault has one). */
function otherCreates(vaultId: string, name: string, id: string = core.newId()): string {
  withKey(vaultId, (key, vault) => {
    const enc = key.encryptItem(login(name), id, vaultId) as { key: string; data: string };
    if (vault.manifestSeq > 0) {
      const next = key.manifestNext(vaultId, vault.epoch, vault.manifestSeq, vault.manifest!, [], [{ id, deleted_at: null, data: enc.data }]) as Entry;
      Object.assign(vault, { manifest: next.sealed, manifestSeq: next.seq });
    }
    bump(vaultId);
    w.items.set(id, { id, vault_id: vaultId, item_key: enc.key, data: enc.data, revision: w.clock * 1000, deleted_at: null, created_at: 1, updated_at: 1, at: w.clock });
  });
  return id;
}

/** Another device starts the vault's first manifest. */
function otherStarts(vaultId: string) {
  withKey(vaultId, (key, vault) => {
    Object.assign(vault, { manifest: key.manifestStart(vaultId, vault.epoch, 1, rowsOf(vaultId)), manifestSeq: 1 });
    bump(vaultId);
  });
}

/** The server changes a row behind the members' backs (it shows as a change in the next delta). */
function tamper(fn: () => string) {
  w.clock++;
  w.revision++;
  const vaultId = fn();
  w.vaults.get(vaultId)!.seq++;
}

function newWorld(opts: { manifests?: boolean; ok?: boolean } = {}) {
  h.config = { features: [...FEATURES], limits: {} };
  h.handler = handle;
  storage.clear();
  const first = alice.account.openVaultKey(v.vault.id, v.vault.wrappedKey, "account", 0, true);
  const nv = alice.account.newVaultKey(B);
  const second = nv.takeKey();
  w = {
    revision: 1,
    clock: 1,
    vaults: new Map([
      [v.vault.id, { id: v.vault.id, meta: first.encryptMeta(v.vault.id, { name: "Personal" }), wrapped: v.vault.wrappedKey, epoch: 0, seq: 1, role: "owner", manifest: null, manifestSeq: 0, manifestOk: opts.ok ?? false }],
      [B, { id: B, meta: second.encryptMeta(B, { name: "Second" }), wrapped: nv.wrapped, epoch: 0, seq: 1, role: "owner", manifest: null, manifestSeq: 0, manifestOk: opts.ok ?? false }],
    ]),
    items: new Map(),
    tombs: [],
    pins: { key_pins: null, seq: 0 },
    calls: [],
    next: [],
    serverTime: 100_000_000,
    trashDays: 30,
    bare: new Set(),
  };
  first.free();
  second.free();
  nv.free();
  otherCreates(A(), "Mail", "item-1");
  otherCreates(A(), "Bank", "item-2");
  if (opts.manifests) {
    otherStarts(A());
    otherStarts(B);
  }
}

async function signIn() {
  lock();
  await boot();
  const a = v.accounts.find((x) => x.name === "alice")!;
  await restoreUnlocked(a.id, unb64(a.sessionBytes));
  await settled();
  w.calls = [];
}

/** Let the background work after a sync (starting a manifest, deleting old trash) finish. */
async function settled() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));
}

const calls = (pred: (c: World["calls"][number]) => boolean) => w.calls.filter(pred);
const synced = () => calls((c) => c.path.startsWith("/sync") && c.path !== "/sync/revision");
const lastBody = (pred: (c: World["calls"][number]) => boolean) => calls(pred).at(-1)!.body as Record<string, unknown> & { manifests?: Entry[] };
const entry = (name: string) => getState().items.find((i) => i.item.name === name)!;
const vaultState = (id: string) => getState().vaults.find((x) => x.id === id)!;
const remembered = (): Record<string, number> => JSON.parse(storage.get(manifestsKey(`https://vault.example.test|${alice.id}`)) ?? "{}");
const names = () =>
  getState()
    .items.map((i) => i.item.name)
    .sort();

beforeEach(() => newWorld({ manifests: true }));

// ------------------------------------------------------------------- tests

describe("vaults without a manifest", () => {
  beforeEach(() => newWorld());

  it("get exactly the requests from before: no manifests, no query, no revision on trash, restore and delete", async () => {
    await signIn();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    const id = await createItem(A(), login("Shop"));
    await updateItem(entry("Shop"), { ...entry("Shop").item, name: "Shop 2" });
    await updateItem(entry("Shop 2"), entry("Shop 2").item, B);
    await trashItem(id);
    await restoreItem(id);
    await trashItem(id);
    await purgeItem(id);
    await importItems(A(), [login("One"), login("Two")]);
    await rotateVaultKey(A());
    await settled();
    for (const c of w.calls) {
      expect(c.path, c.path).not.toContain("manifest");
      expect(c.path, c.path).not.toContain("revision=");
      expect((c.body as { manifests?: unknown } | undefined)?.manifests, c.path).toBeUndefined();
    }
    expect(names()).toEqual(["Bank", "Mail", "One", "Two"]);
    expect(remembered()).toEqual({});
    expect(getState().vaults.some((x) => x.manifestWarning)).toBe(false);
  });

  it("no first manifest is started while the server says some app isn't ready, or without the feature", async () => {
    await signIn();
    await syncNow();
    await settled();
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
    w.vaults.get(A())!.manifestOk = true;
    h.config = { features: FEATURES.filter((f) => f !== "vault_manifest") };
    tamper(() => A());
    await syncNow();
    await settled();
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
  });
});

describe("starting a vault's first manifest", () => {
  it("after a sync that says every app is ready: version 1 over every row, pinned to the vault's number, shown without another sync", async () => {
    newWorld({ ok: true });
    await signIn();
    // Both vaults were started by the sign-in's sync (cleared from the log by signIn): they check out on the server.
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 1, live: 2, trashed: 0 });
    expect(serverCheck(B)).toMatchObject({ status: "ok", version: 1, live: 0 });
    expect(remembered()).toEqual({ [A()]: 1, [B]: 1 });
    // The next write builds on it without a sync in between.
    await createItem(A(), login("Shop"));
    expect(lastBody((c) => c.path === "/items").manifests).toMatchObject([{ vault_id: A(), seq: 2 }]);
    expect(synced()).toEqual([]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 2, live: 3 });
  });

  it("sends base_seq 0, seq 1 and the vault's seq of that answer, once per answer; a refusal is ignored", async () => {
    newWorld();
    await signIn();
    w.vaults.get(A())!.manifestOk = true;
    tamper(() => A());
    const seq = w.vaults.get(A())!.seq;
    w.next.push({
      path: `/vaults/${A()}/manifest`,
      run: () => {
        throw err(409, "manifest_not_ready");
      },
    });
    await syncNow();
    await settled();
    const puts = calls((c) => c.path === `/vaults/${A()}/manifest`);
    expect(puts).toHaveLength(1);
    expect(puts[0]).toMatchObject({ method: "PUT", body: { base_seq: 0, seq: 1, vault_seq: seq } });
    expect(remembered()).toEqual({});
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    // The next answer decides again.
    tamper(() => A());
    await syncNow();
    await settled();
    expect(calls((c) => c.path === `/vaults/${A()}/manifest`)).toHaveLength(2);
    expect(serverCheck(A()).status).toBe("ok");
    expect(remembered()).toEqual({ [A()]: 1 });
  });

  it("never by a member who can only read", async () => {
    newWorld({ ok: true });
    w.vaults.get(A())!.role = "read";
    w.vaults.get(B)!.role = "read";
    await signIn();
    expect(w.vaults.get(A())!.manifestSeq).toBe(0);
    expect(remembered()).toEqual({});
  });
});

describe("writes carry the vault's next manifest", () => {
  it("create and edit: one version up each, shown without asking the server, remembered", async () => {
    await signIn();
    const id = await createItem(A(), login("Shop"));
    expect(lastBody((c) => c.path === "/items").manifests).toMatchObject([{ vault_id: A(), seq: 2 }]);
    await updateItem(entry("Shop"), { ...entry("Shop").item, name: "Shop 2" });
    expect(lastBody((c) => c.path === `/items/${id}`).manifests).toMatchObject([{ vault_id: A(), seq: 3 }]);
    expect(synced()).toEqual([]);
    expect(names()).toEqual(["Bank", "Mail", "Shop 2"]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 3, trashed: 0 });
    expect(remembered()[A()]).toBe(3);
    // A full sync agrees.
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("trash, restore and delete for good: the item's revision and the manifest in the query", async () => {
    await signIn();
    const rev = w.items.get("item-1")!.revision;
    await trashItem("item-1");
    const trash = calls((c) => c.method === "DELETE").at(-1)!;
    expect(trash.path).toMatch(new RegExp(`^/items/item-1\\?revision=${rev}&manifest_seq=2&manifest=[A-Za-z0-9_-]+$`));
    expect(trash.body).toBeUndefined();
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 2, live: 1, trashed: 1 });
    await restoreItem("item-1");
    expect(calls((c) => c.method === "POST").at(-1)!.path).toMatch(/^\/items\/item-1\/restore\?revision=\d+&manifest_seq=3&manifest=/);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 2, trashed: 0 });
    await trashItem("item-1");
    await purgeItem("item-1");
    expect(calls((c) => c.method === "DELETE").at(-1)!.path).toMatch(/^\/items\/item-1\/permanent\?revision=\d+&manifest_seq=5&manifest=/);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 5, live: 1, trashed: 0 });
    expect(names()).toEqual(["Bank"]);
    expect(remembered()[A()]).toBe(5);
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("a move carries one manifest for each vault: out of the old one, the re-encrypted item into the new one", async () => {
    await signIn();
    await updateItem(entry("Mail"), entry("Mail").item, B);
    const body = lastBody((c) => c.path === "/items/item-1");
    expect(body.manifests).toHaveLength(2);
    expect(body.manifests).toEqual(expect.arrayContaining([expect.objectContaining({ vault_id: A(), seq: 2 }), expect.objectContaining({ vault_id: B, seq: 2 })]));
    expect(serverCheck(A())).toMatchObject({ status: "ok", live: 1 });
    expect(serverCheck(B)).toMatchObject({ status: "ok", live: 1 });
    expect(entry("Mail").vaultId).toBe(B);
    expect(getState().vaults.some((x) => x.manifestWarning)).toBe(false);
    expect(remembered()).toEqual({ [A()]: 2, [B]: 2 });
  });

  it("a move into a vault without a manifest carries only the old vault's (and the other way round)", async () => {
    Object.assign(w.vaults.get(B)!, { manifest: null, manifestSeq: 0 });
    await signIn();
    await updateItem(entry("Mail"), entry("Mail").item, B);
    expect(lastBody((c) => c.path === "/items/item-1").manifests).toMatchObject([{ vault_id: A(), seq: 2 }]);
    await updateItem(entry("Mail"), entry("Mail").item, A());
    expect(lastBody((c) => c.path === "/items/item-1").manifests).toMatchObject([{ vault_id: A(), seq: 3 }]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", live: 2 });
  });

  it("an import chains its batches from its own manifests, without a sync in between", async () => {
    await signIn();
    await importItems(A(), [login("One"), login("Two"), login("Three"), login("Four"), login("Five")], undefined, { max_import_items: 2 });
    const batches = calls((c) => c.path === "/items/import").map((c) => (c.body as { manifests: Entry[]; items: unknown[] }));
    expect(batches.map((b) => b.items.length)).toEqual([2, 2, 1]);
    expect(batches.map((b) => b.manifests[0].seq)).toEqual([2, 3, 4]);
    // Only the sync that ends the import.
    expect(synced()).toHaveLength(1);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 4, live: 7 });
    expect(names()).toEqual(["Bank", "Five", "Four", "Mail", "One", "Three", "Two"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("an import batch that meets another device's write is sent again with a new manifest", async () => {
    await signIn();
    w.next.push({ path: "/items/import", run: () => void otherCreates(A(), "Elsewhere") });
    await importItems(A(), [login("One"), login("Two")]);
    const batches = calls((c) => c.path === "/items/import").map((c) => (c.body as { manifests: Entry[]; items: { id: string }[] }));
    expect(batches.map((b) => b.manifests[0].seq)).toEqual([2, 3]);
    expect(batches[0].items.map((i) => i.id)).toEqual(batches[1].items.map((i) => i.id));
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 5 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("a key replacement carries a whole new manifest, sealed with the new key for the new epoch", async () => {
    await signIn();
    await trashItem("item-2");
    await rotateVaultKey(A());
    const body = lastBody((c) => c.path === `/vaults/${A()}/rotate`);
    expect(body.manifests).toMatchObject([{ vault_id: A(), seq: 3 }]);
    expect(w.vaults.get(A())!.epoch).toBe(1);
    // Checked with the new key at the new epoch; the trashed item is still counted as trashed.
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 1, trashed: 1 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(3);
    // And the next write builds on it.
    await createItem(A(), login("Shop"));
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 4, live: 2, trashed: 1 });
  });

  it("restoring an earlier version is an ordinary edit with its manifest", async () => {
    await signIn();
    await restoreItemVersion(entry("Mail"), { ...entry("Mail").item, name: "Mail (older)" });
    expect(lastBody((c) => c.path === "/items/item-1").manifests).toMatchObject([{ vault_id: A(), seq: 2 }]);
    expect(serverCheck(A()).status).toBe("ok");
  });
});

describe("showing an own write without asking the server", () => {
  it("only when the answer's manifest version is the one sent; otherwise the sync that follows checks the vault", async () => {
    await signIn();
    const real = h.handler!;
    // The server answers a create with another manifest version than the one this app sent.
    h.handler = async (path, opts) => {
      const answer = await real(path, opts);
      return path === "/items" ? { ...(answer as object), manifest_seq: 9 } : answer;
    };
    await createItem(A(), login("Shop"));
    h.handler = real;
    expect(synced()).toHaveLength(1);
    expect(names()).toEqual(["Bank", "Mail", "Shop"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(2);
  });

  it("an answer without a manifest version is never shown as sent", async () => {
    await signIn();
    const real = h.handler!;
    h.handler = async (path, opts) => {
      const answer = (await real(path, opts)) as Record<string, unknown>;
      if (path !== "/items") return answer;
      const { manifest_seq: _dropped, ...rest } = answer;
      return rest;
    };
    await createItem(A(), login("Shop"));
    h.handler = real;
    expect(synced()).toHaveLength(1);
    expect(names()).toEqual(["Bank", "Mail", "Shop"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });
});

describe("when the vault changed on another device", () => {
  it("a create syncs, checks and is sent again with the same id", async () => {
    await signIn();
    w.next.push({ path: "/items", method: "POST", run: () => void otherCreates(A(), "Elsewhere") });
    const id = await createItem(A(), login("Shop"));
    const posts = calls((c) => c.path === "/items");
    expect(posts.map((c) => (c.body as { manifests: Entry[] }).manifests[0].seq)).toEqual([2, 3]);
    expect(posts.map((c) => (c.body as { id: string }).id)).toEqual([id, id]);
    expect(names()).toEqual(["Bank", "Elsewhere", "Mail", "Shop"]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 4 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("an edit of an item nobody else touched is sent again; three conflicts in a row end it", async () => {
    await signIn();
    w.next.push({ path: "/items/item-1", run: () => void otherCreates(A(), "Elsewhere") });
    await updateItem(entry("Mail"), { ...entry("Mail").item, name: "Mail 2" });
    expect(calls((c) => c.path === "/items/item-1")).toHaveLength(2);
    expect(names()).toEqual(["Bank", "Elsewhere", "Mail 2"]);
    expect(serverCheck(A()).status).toBe("ok");

    w.calls = [];
    for (let n = 0; n < 3; n++) w.next.push({ path: "/items/item-2", run: () => void otherCreates(A(), `Busy ${n}`) });
    await expect(updateItem(entry("Bank"), { ...entry("Bank").item, name: "Bank 2" })).rejects.toThrow(MANIFEST_BUSY);
    expect(calls((c) => c.path === "/items/item-2")).toHaveLength(3);
    expect(names()).toContain("Bank");
    expect(serverCheck(A()).status).toBe("ok");
  });

  it("an edit stops when the item itself changed elsewhere (the existing conflict), and when it is gone", async () => {
    await signIn();
    const mine = entry("Mail");
    w.next.push({
      path: "/items/item-1",
      run: () =>
        withKey(A(), (key, vault) => {
          const have = w.items.get("item-1")!;
          const enc = key.updateItem({ id: have.id, vault_id: A(), key: have.item_key, data: have.data }, { ...login("Mail elsewhere"), rev: 1 }) as { key: string; data: string };
          const next = key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifest!, [have], [{ id: have.id, deleted_at: null, data: enc.data }]) as Entry;
          Object.assign(vault, { manifest: next.sealed, manifestSeq: next.seq });
          bump(A());
          // The same revision, so the server reports the manifest (not the item) as what moved.
          w.items.set(have.id, { ...have, item_key: enc.key, data: enc.data, at: w.clock });
        }),
    });
    await expect(updateItem(mine, { ...mine.item, name: "Mail mine" })).rejects.toThrow("changed on another device or by someone you share");
    expect(calls((c) => c.path === "/items/item-1")).toHaveLength(1);
    expect(entry("Mail elsewhere")).toBeTruthy();
  });

  it("trash: sent again; nothing to do when the item is already in the trash or gone", async () => {
    await signIn();
    w.next.push({ path: "/items/item-1", method: "DELETE", run: () => void otherCreates(A(), "Elsewhere") });
    await trashItem("item-1");
    expect(calls((c) => c.method === "DELETE")).toHaveLength(2);
    expect(serverCheck(A())).toMatchObject({ status: "ok", trashed: 1 });

    // Another device trashed item-2 first: this app's request meets a revision conflict, syncs and finds it done.
    w.calls = [];
    w.next.push({
      path: "/items/item-2",
      method: "DELETE",
      run: () =>
        withKey(A(), (key, vault) => {
          const have = w.items.get("item-2")!;
          const next = key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifest!, [have], [{ ...have, deleted_at: w.serverTime - 5 }]) as Entry;
          Object.assign(vault, { manifest: next.sealed, manifestSeq: next.seq });
          bump(A());
          w.items.set(have.id, { ...have, deleted_at: w.serverTime - 5, revision: w.clock * 1000, at: w.clock });
        }),
    });
    await trashItem("item-2");
    expect(calls((c) => c.method === "DELETE")).toHaveLength(1);
    expect(entry("Bank").deletedAt).toBe(w.serverTime - 5);
    expect(serverCheck(A())).toMatchObject({ status: "ok", trashed: 2 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("a copy that still said 'no manifest' (400 manifest_required): sync, then the write goes out with one", async () => {
    newWorld();
    await signIn();
    w.next.push({ path: "/items", method: "POST", run: () => otherStarts(A()) });
    await createItem(A(), login("Shop"));
    const posts = calls((c) => c.path === "/items").map((c) => (c.body as { manifests?: Entry[] }).manifests);
    expect(posts[0]).toBeUndefined();
    expect(posts[1]).toMatchObject([{ vault_id: A(), seq: 2 }]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 2, live: 3 });

    w.calls = [];
    w.next.push({ path: "/items/item-1", method: "PUT", run: () => otherStarts(B) });
    await updateItem(entry("Mail"), entry("Mail").item, B);
    const moves = calls((c) => c.path === "/items/item-1").map((c) => (c.body as { manifests: Entry[] }).manifests.map((m) => m.vault_id).sort());
    expect(moves).toEqual([[A()], [A(), B].sort()]);
    expect(serverCheck(B)).toMatchObject({ status: "ok", version: 2, live: 1 });
    expect(serverCheck(A())).toMatchObject({ status: "ok", live: 2 });
    expect(getState().vaults.some((x) => x.manifestWarning)).toBe(false);
  });

  it("a key replacement is redone from a fresh sync", async () => {
    await signIn();
    w.next.push({ path: `/vaults/${A()}/rotate`, run: () => void otherCreates(A(), "Elsewhere") });
    await rotateVaultKey(A());
    const rotations = calls((c) => c.path === `/vaults/${A()}/rotate`).map((c) => c.body as { manifests: Entry[]; items: unknown[] });
    expect(rotations.map((r) => r.manifests[0].seq)).toEqual([2, 3]);
    expect(rotations.map((r) => r.items.length)).toEqual([2, 3]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 3 });
  });
});

describe("checking every sync answer", () => {
  it("an older copy of an item: the vault shows its warning, keeps its items, and takes no writes", async () => {
    await signIn();
    const old = { ...w.items.get("item-1")! };
    await updateItem(entry("Mail"), { ...entry("Mail").item, name: "Mail 2" });
    expect(remembered()[A()]).toBe(2);
    tamper(() => {
      w.items.set("item-1", { ...old, revision: w.items.get("item-1")!.revision, at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(vaultState(B).manifestWarning).toBeUndefined();
    expect(names()).toContain("Bank");
    // Nothing remembered changed.
    expect(remembered()[A()]).toBe(2);
    w.calls = [];
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_HELD);
    await expect(updateItem(entry("Bank"), { ...entry("Bank").item, name: "Bank 2" })).rejects.toThrow(MANIFEST_HELD);
    await expect(trashItem("item-2")).rejects.toThrow(MANIFEST_HELD);
    await expect(restoreItem("item-2")).rejects.toThrow(MANIFEST_HELD);
    await expect(purgeItem("item-2")).rejects.toThrow(MANIFEST_HELD);
    await expect(importItems(A(), [login("One")])).rejects.toThrow(MANIFEST_HELD);
    await expect(updateItem(entry("Bank"), entry("Bank").item, B)).rejects.toThrow(MANIFEST_HELD);
    await expect(rotateVaultKey(A())).rejects.toThrow(MANIFEST_HELD);
    expect(calls((c) => c.method !== "GET")).toEqual([]);
    // The other vault is written as ever, but nothing moves into the unresolved one.
    const id = await createItem(B, login("Elsewhere"));
    await expect(updateItem(entry("Elsewhere"), entry("Elsewhere").item, A())).rejects.toThrow(MANIFEST_HELD);
    expect(w.items.get(id)!.vault_id).toBe(B);
  });

  it("a hidden item, a hidden deletion and a deleted item brought back all show the warning", async () => {
    await signIn();
    const gone = { ...w.items.get("item-2")! };
    // Hidden: the server drops a row.
    tamper(() => {
      w.items.delete("item-2");
      w.tombs.push({ id: "item-2", vault_id: A(), at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    // Put back: the warning clears by itself with the next answer that checks out.
    tamper(() => {
      w.items.set("item-2", { ...gone, at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    // Deleted for good by this app, then brought back by the server.
    await trashItem("item-2");
    await purgeItem("item-2");
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    tamper(() => {
      w.items.set("item-2", { ...gone, at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(names()).toEqual(["Bank", "Mail"]);
  });

  it("an earlier state of the whole vault (older manifest and items) is a rollback on a device that saw a later one", async () => {
    await signIn();
    const before = { vault: { ...w.vaults.get(A())! }, items: new Map(w.items) };
    await createItem(A(), login("Shop"));
    await syncNow();
    expect(remembered()[A()]).toBe(2);
    tamper(() => {
      Object.assign(w.vaults.get(A())!, { manifest: before.vault.manifest, manifestSeq: before.vault.manifestSeq });
      for (const [id, row] of w.items) if (!before.items.has(id)) {
        w.items.delete(id);
        w.tombs.push({ id, vault_id: row.vault_id, at: w.clock });
      }
      return A();
    });
    // The server's copy is consistent in itself (a fresh device would accept it)...
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 1 });
    await syncNow();
    // ...but this device remembers version 2.
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(remembered()[A()]).toBe(2);
  });

  it("no manifest after one was seen is a rollback, also when the server stops listing the feature", async () => {
    await signIn();
    expect(remembered()[A()]).toBe(1);
    h.config = { features: FEATURES.filter((f) => f !== "vault_manifest") };
    tamper(() => {
      Object.assign(w.vaults.get(A())!, { manifest: null, manifestSeq: 0 });
      return A();
    });
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(vaultState(B).manifestWarning).toBeUndefined();
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_HELD);
    // And no new first manifest is started over it.
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
  });

  it("a locked and unlocked vault is checked against what the device remembers", async () => {
    await signIn();
    await createItem(A(), login("Shop"));
    const before = { ...w.vaults.get(A())! };
    await createItem(A(), login("Shop 2"));
    lock();
    tamper(() => {
      Object.assign(w.vaults.get(A())!, { manifest: before.manifest, manifestSeq: before.manifestSeq });
      const id = [...w.items.values()].find((r) => r.at === w.clock - 1)!.id;
      w.items.delete(id);
      return A();
    });
    await signIn();
    expect(vaultState(A()).manifestWarning).toBe(true);
  });

  it("a row that comes without its data makes the app fetch the whole account once", async () => {
    await signIn();
    tamper(() => {
      w.items.set("item-1", { ...w.items.get("item-1")!, at: w.clock });
      return A();
    });
    w.bare.add("item-1");
    await syncNow();
    expect(synced().map((c) => c.path.startsWith("/sync?since="))).toEqual([true, false]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    // Still without its data in the full answer: the warning stays, and nothing is fetched a third time.
    w.calls = [];
    tamper(() => {
      w.items.set("item-1", { ...w.items.get("item-1")!, at: w.clock });
      return A();
    });
    const real = h.handler!;
    h.handler = async (path, opts) => {
      w.bare.add("item-1");
      return real(path, opts);
    };
    await syncNow();
    h.handler = real;
    expect(synced()).toHaveLength(2);
    expect(vaultState(A()).manifestWarning).toBe(true);
  });
});

describe("Use the server's copy", () => {
  async function unresolved() {
    await signIn();
    await createItem(A(), login("Shop"));
    await createItem(A(), login("Shop 2"));
    expect(remembered()[A()]).toBe(3);
    tamper(() => {
      w.items.delete("item-2");
      w.tombs.push({ id: "item-2", vault_id: A(), at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    w.calls = [];
  }

  it("fetches everything afresh and stores a baseline above the server's and the remembered version", async () => {
    await unresolved();
    await acceptServerCopy(A());
    expect(synced()[0].path).toBe("/sync");
    const put = calls((c) => c.path === `/vaults/${A()}/manifest`);
    expect(put).toHaveLength(1);
    expect(put[0].body).toMatchObject({ base_seq: 3, seq: 4, vault_seq: w.vaults.get(A())!.seq - 1 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 4, live: 3 });
    expect(remembered()[A()]).toBe(4);
    // Writes go on from the baseline.
    await createItem(A(), login("After"));
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 5, live: 4 });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("jumps above a higher remembered version after the server went back to an earlier state", async () => {
    await signIn();
    const before = { ...w.vaults.get(A())! };
    await createItem(A(), login("Shop"));
    await createItem(A(), login("Shop 2"));
    tamper(() => {
      Object.assign(w.vaults.get(A())!, { manifest: before.manifest, manifestSeq: before.manifestSeq });
      for (const [id, row] of w.items) if (row.at > 3 && id !== "item-1" && id !== "item-2") w.items.delete(id);
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    w.calls = [];
    await acceptServerCopy(A());
    expect(calls((c) => c.path === `/vaults/${A()}/manifest`)[0].body).toMatchObject({ base_seq: 1, seq: 4 });
    expect(remembered()[A()]).toBe(4);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(names()).toEqual(["Bank", "Mail"]);
  });

  it("tries again when the vault changed meanwhile, and says so after three tries", async () => {
    await unresolved();
    w.next.push({ path: `/vaults/${A()}/manifest`, run: () => void tamper(() => A()) });
    await acceptServerCopy(A());
    expect(calls((c) => c.path === `/vaults/${A()}/manifest`)).toHaveLength(2);
    expect(vaultState(A()).manifestWarning).toBeUndefined();

    await unresolvedAgain();
    for (let n = 0; n < 3; n++) w.next.push({ path: `/vaults/${A()}/manifest`, run: () => void tamper(() => A()) });
    await expect(acceptServerCopy(A())).rejects.toThrow(MANIFEST_BUSY);
    expect(calls((c) => c.path === `/vaults/${A()}/manifest`)).toHaveLength(3);
    expect(vaultState(A()).manifestWarning).toBe(true);
  });
  async function unresolvedAgain() {
    tamper(() => {
      w.items.delete("item-1");
      w.tombs.push({ id: "item-1", vault_id: A(), at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    w.calls = [];
  }

  it("a manifest that vanished can't be replaced while some member's app is too old", async () => {
    await signIn();
    tamper(() => {
      Object.assign(w.vaults.get(A())!, { manifest: null, manifestSeq: 0, manifestOk: false });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    w.calls = [];
    await expect(acceptServerCopy(A())).rejects.toThrow(MANIFEST_NOT_READY);
    expect(calls((c) => c.path === `/vaults/${A()}/manifest`)[0].body).toMatchObject({ base_seq: 0, seq: 2 });
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(remembered()[A()]).toBe(1);
  });

  it("does nothing when the fresh answer checks out, and isn't offered to someone who can only read", async () => {
    await signIn();
    await acceptServerCopy(A());
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
    await unresolvedAgain();
    w.vaults.get(A())!.role = "read";
    await expect(acceptServerCopy(A())).rejects.toThrow("Only someone who can edit");
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
    await expect(trashItem("item-2")).rejects.toThrow(MANIFEST_HELD);
  });
});

describe("old trash", () => {
  /** Put an item in vault A's trash at `deletedAt`, the right way. */
  function otherTrashes(id: string, deletedAt: number) {
    withKey(A(), (key, vault) => {
      const have = w.items.get(id)!;
      if (vault.manifestSeq > 0) {
        const next = key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifest!, [have], [{ ...have, deleted_at: deletedAt }]) as Entry;
        Object.assign(vault, { manifest: next.sealed, manifestSeq: next.seq });
      }
      bump(A());
      w.items.set(id, { ...have, deleted_at: deletedAt, revision: w.clock * 1000, at: w.clock });
    });
  }

  it("is deleted by the app after a sync that checked out, as one vault write with the next manifest", async () => {
    const due = otherCreates(A(), "Due");
    const fresh = otherCreates(A(), "Fresh");
    otherTrashes(due, w.serverTime - 31 * DAY);
    otherTrashes(fresh, w.serverTime - 29 * DAY);
    const rev = w.items.get(due)!.revision;
    lock();
    await boot();
    const a = v.accounts.find((x) => x.name === "alice")!;
    await restoreUnlocked(a.id, unb64(a.sessionBytes));
    await settled();
    const purges = calls((c) => c.path === `/vaults/${A()}/trash/purge`);
    expect(purges).toHaveLength(1);
    expect(purges[0].body).toMatchObject({ items: [{ id: due, revision: rev }], manifests: [{ vault_id: A(), seq: 6 }] });
    expect(w.items.has(due)).toBe(false);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 6, live: 2, trashed: 1 });
    expect(names()).toEqual(["Bank", "Fresh", "Mail"]);
    expect(remembered()[A()]).toBe(6);
    // Shown without asking the server again.
    expect(w.calls.at(-1)!.path).toBe(`/vaults/${A()}/trash/purge`);
    // Shown without another sync, and the next sync agrees.
    w.calls = [];
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(calls((c) => c.path.endsWith("/trash/purge"))).toEqual([]);
  });

  it("one attempt: a refusal is ignored and nothing is retried until the next sync", async () => {
    const due = otherCreates(A(), "Due");
    otherTrashes(due, w.serverTime - 31 * DAY);
    w.next.push({
      path: `/vaults/${A()}/trash/purge`,
      run: () => {
        throw err(409, "manifest_conflict");
      },
    });
    await signIn();
    expect(w.items.has(due)).toBe(true);
    expect(calls((c) => c.path.endsWith("/trash/purge"))).toEqual([]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("in chunks of the server's limit, each with its own next manifest", async () => {
    for (let n = 0; n < 5; n++) otherTrashes(otherCreates(A(), `Due ${n}`), 5);
    h.config = { features: [...FEATURES], limits: { max_import_items: 2 } };
    lock();
    await boot();
    const a = v.accounts.find((x) => x.name === "alice")!;
    w.calls = [];
    const config = h.config;
    await restoreUnlocked(a.id, unb64(a.sessionBytes));
    h.config = config;
    await settled();
    const purges = calls((c) => c.path === `/vaults/${A()}/trash/purge`).map((c) => c.body as { items: unknown[]; manifests: Entry[] });
    expect(purges.map((p) => p.items.length)).toEqual([2, 2, 1]);
    expect(purges.map((p) => p.manifests[0].seq)).toEqual([12, 13, 14]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", live: 2, trashed: 0 });
  });

  it("never in a vault without a manifest (the server sweeps it), with a server that keeps the trash forever, or as a reader", async () => {
    newWorld();
    otherTrashes("item-1", 5);
    await signIn();
    await syncNow();
    await settled();
    expect(calls((c) => c.path.endsWith("/trash/purge"))).toEqual([]);

    newWorld({ manifests: true });
    otherTrashes("item-1", 5);
    w.trashDays = 0;
    await signIn();
    expect(w.items.has("item-1")).toBe(true);
    w.trashDays = 30;
    w.vaults.get(A())!.role = "read";
    tamper(() => B);
    await syncNow();
    await settled();
    expect(w.items.has("item-1")).toBe(true);
  });

  it("never in a vault that doesn't check out", async () => {
    otherTrashes("item-1", 5);
    w.items.set("item-2", { ...w.items.get("item-2")!, data: w.items.get("item-1")!.data });
    await signIn();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(w.items.has("item-1")).toBe(true);
  });
});
