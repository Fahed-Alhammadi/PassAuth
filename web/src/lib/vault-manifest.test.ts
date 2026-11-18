/**
 * Vault manifests through `vault.ts` against a fake server that keeps manifests like the real one (real core): every
 * write carries the vault's next manifest, own writes are shown without asking only when the answer agrees, conflicts
 * are retried at most three times, every sync answer is checked (warning, writes held back, device memory), a first
 * manifest is started when the server says every app is ready, "Use the server's copy" writes a new baseline, and due
 * trash is deleted by the app. Vaults without a manifest get exactly the requests from before.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
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

import { ApiError, UnreachableError } from "./api";
import { ROLLBACK_SHOWN } from "./item-revs";
import { MANIFEST_BUSY, MANIFEST_HELD, MANIFEST_HIDDEN, MANIFEST_NOT_READY, MANIFEST_UNCHECKED, manifestsKey } from "./manifest";
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
  manifestPrev: string | null;
  manifestOk: boolean;
  /** The manifest log: one entry for each manifest stored, oldest first. */
  log: { seq: number; prev: string; digest: string }[];
}
interface Entry {
  vault_id: string;
  seq: number;
  prev: string;
  sealed: string;
}
type Built = { seq: number; prev: string; sealed: string; link: string };
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
  /** Entries a manifest-log answer holds at most. */
  logPage: number;
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
  withKey(vaultId, (key, vault) => key.manifestVerify(vaultId, vault.epoch, vault.manifestSeq, vault.manifestPrev, vault.manifest, null, null, null, rowsOf(vaultId)) as { status: string; version: number; link: string | null; live: number; trashed: number });
/** The link of the vault's current manifest on the fake server (null: none). */
const linkOf = (vault: VaultState): string | null => (vault.manifestSeq > 0 ? core.manifestLink(vault.manifestSeq, vault.manifestPrev!, vault.manifest!) : null);
const ZERO = "A".repeat(43);
/** Store a manifest as the vault's current one, with its log entry (the real server keeps one for every manifest). */
function setManifest(vault: VaultState, m: { seq: number; prev: string; sealed: string }) {
  Object.assign(vault, { manifest: m.sealed, manifestSeq: m.seq, manifestPrev: m.prev });
  vault.log.push({ seq: m.seq, prev: m.prev, digest: core.manifestDataHash(m.sealed) });
}

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
    if (typeof m.prev !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(m.prev)) throw err(400, "bad_request");
    if (vault.manifestSeq === 0 || m.seq !== vault.manifestSeq + 1 || m.prev !== linkOf(vault)) throw err(409, "manifest_conflict");
  }
  for (const id of affected) if (w.vaults.get(id)!.manifestSeq > 0 && !sent.some((m) => m.vault_id === id)) throw err(400, "manifest_required");
}
function storeManifests(sent: Entry[]) {
  for (const m of sent) {
    // A request never carries the device's link.
    if ("link" in m) throw err(400, "bad_request");
    setManifest(w.vaults.get(m.vault_id)!, m);
  }
}
const entriesOf = (b: Record<string, unknown>): Entry[] => (Array.isArray(b.manifests) ? (b.manifests as Entry[]) : []);
function queryOf(path: string, vaultId: string): { path: string; revision?: number; sent: Entry[] } {
  const [bare, query = ""] = path.split("?");
  const q = new URLSearchParams(query);
  const seq = q.get("manifest_seq");
  const sealed = q.get("manifest");
  const prev = q.get("manifest_prev");
  if ((seq === null) !== (sealed === null) || (seq === null) !== (prev === null)) throw err(400, "bad_request");
  return { path: bare, ...(q.has("revision") ? { revision: Number(q.get("revision")) } : {}), sent: seq !== null ? [{ vault_id: vaultId, seq: Number(seq), prev: prev!, sealed: sealed! }] : [] };
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
      manifest_prev: x.manifestSeq > 0 ? x.manifestPrev : null,
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
  const log = /^\/vaults\/([^/]+)\/manifest-log\?after=(\d+)$/.exec(path);
  if (log && method === "GET") {
    const vault = w.vaults.get(log[1]);
    if (!vault) throw err(404, "not_found");
    const entries = vault.log.filter((e) => e.seq > Number(log[2]));
    return { entries: entries.slice(0, w.logPage), more: entries.length > w.logPage };
  }

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
    if (typeof b.prev !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(b.prev)) throw err(400, "bad_request");
    if (vault.manifestSeq !== b.base_seq || vault.seq !== b.vault_seq || !((b.seq as number) > (b.base_seq as number)) || b.prev !== (linkOf(vault) ?? ZERO)) throw err(409, "manifest_conflict");
    if ((b.seq as number) - (b.base_seq as number) > 1_000_000) throw err(400, "bad_request");
    if (vault.manifestSeq === 0 && !vault.manifestOk) throw err(409, "manifest_not_ready");
    const seq = bump(vault.id);
    setManifest(vault, b as unknown as Entry);
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
      setManifest(vault, key.manifestNext(vaultId, vault.epoch, vault.manifestSeq, vault.manifestPrev!, vault.manifest!, [], [{ id, deleted_at: null, data: enc.data }]) as Built);
    }
    bump(vaultId);
    w.items.set(id, { id, vault_id: vaultId, item_key: enc.key, data: enc.data, revision: w.clock * 1000, deleted_at: null, created_at: 1, updated_at: 1, at: w.clock });
  });
  return id;
}

/** Another device starts the vault's first manifest. */
function otherStarts(vaultId: string) {
  withKey(vaultId, (key, vault) => {
    setManifest(vault, key.manifestStart(vaultId, vault.epoch, 1, null, rowsOf(vaultId)) as Built);
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
      [v.vault.id, { id: v.vault.id, meta: first.encryptMeta(v.vault.id, { name: "Personal" }), wrapped: v.vault.wrappedKey, epoch: 0, seq: 1, role: "owner", manifest: null, manifestSeq: 0, manifestPrev: null, manifestOk: opts.ok ?? false, log: [] }],
      [B, { id: B, meta: second.encryptMeta(B, { name: "Second" }), wrapped: nv.wrapped, epoch: 0, seq: 1, role: "owner", manifest: null, manifestSeq: 0, manifestPrev: null, manifestOk: opts.ok ?? false, log: [] }],
    ]),
    items: new Map(),
    tombs: [],
    pins: { key_pins: null, seq: 0 },
    calls: [],
    next: [],
    serverTime: 100_000_000,
    trashDays: 30,
    bare: new Set(),
    logPage: 2000,
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
const SCOPE = () => `https://vault.example.test|${alice.id}`;
/** What the device remembers, as versions (the links are checked where they matter, `rememberedLinks`). */
const remembered = (): Record<string, number> =>
  Object.fromEntries(Object.entries(JSON.parse(storage.get(manifestsKey(SCOPE())) ?? "{}") as Record<string, { version: number }>).map(([id, r]) => [id, r.version]));
const rememberedLinks = (): Record<string, string> =>
  Object.fromEntries(Object.entries(JSON.parse(storage.get(manifestsKey(SCOPE())) ?? "{}") as Record<string, { link: string }>).map(([id, r]) => [id, r.link]));
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
    expect(trash.path).toMatch(new RegExp(`^/items/item-1\\?revision=${rev}&manifest_seq=2&manifest_prev=[A-Za-z0-9_-]{43}&manifest=[A-Za-z0-9_-]+$`));
    expect(trash.body).toBeUndefined();
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 2, live: 1, trashed: 1 });
    await restoreItem("item-1");
    expect(calls((c) => c.method === "POST").at(-1)!.path).toMatch(/^\/items\/item-1\/restore\?revision=\d+&manifest_seq=3&manifest_prev=[A-Za-z0-9_-]{43}&manifest=/);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3, live: 2, trashed: 0 });
    await trashItem("item-1");
    await purgeItem("item-1");
    expect(calls((c) => c.method === "DELETE").at(-1)!.path).toMatch(/^\/items\/item-1\/permanent\?revision=\d+&manifest_seq=5&manifest_prev=[A-Za-z0-9_-]{43}&manifest=/);
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
          setManifest(vault, key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifestPrev!, vault.manifest!, [have], [{ id: have.id, deleted_at: null, data: enc.data }]) as Built);
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
          setManifest(vault, key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifestPrev!, vault.manifest!, [have], [{ ...have, deleted_at: w.serverTime - 5 }]) as Built);
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
      Object.assign(w.vaults.get(A())!, { manifest: before.vault.manifest, manifestSeq: before.vault.manifestSeq, manifestPrev: before.vault.manifestPrev });
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
      Object.assign(w.vaults.get(A())!, { manifest: before.manifest, manifestSeq: before.manifestSeq, manifestPrev: before.manifestPrev });
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

// ---------------------------------------------------- review fixes, round 1

/** The fake server's whole state at one moment (a backup it can go back to). */
function saveWorld() {
  return {
    vaults: new Map([...w.vaults].map(([id, x]) => [id, { ...x, log: [...x.log] }])),
    items: new Map(w.items),
  };
}
/**
 * The server goes back to `saved` (with `then` run on that state: another device writing on the old branch) and serves
 * the result as a change: rows gone since are tombstoned, vault numbers and the clock only go up, the vault is `reset`
 * in the next delta so every row of it is sent.
 */
function serveBranch(saved: ReturnType<typeof saveWorld>, then: () => void = () => {}) {
  w.clock++;
  w.revision++;
  for (const [id, row] of w.items) if (!saved.items.has(id)) w.tombs.push({ id, vault_id: row.vault_id, at: w.clock });
  const seqs = new Map([...w.vaults].map(([id, x]) => [id, x.seq]));
  w.items = new Map([...saved.items].map(([id, row]) => [id, { ...row, at: w.clock }]));
  w.vaults = new Map([...saved.vaults].map(([id, x]) => [id, { ...x, log: [...x.log], seq: seqs.get(id)! + 1 }]));
  then();
}
const fullSyncs = () => calls((c) => c.path === "/sync");
const logCalls = () => calls((c) => c.path.includes("/manifest-log"));

describe("an answer older than an own write (review 1: the behind answer)", () => {
  it("is never taken over unchecked: the whole account is fetched again, and a server that keeps answering so gets the warning", async () => {
    await signIn();
    const old = (await handle("/sync", {})) as Record<string, unknown>;
    await createItem(A(), login("Shop"));
    expect(names()).toEqual(["Bank", "Mail", "Shop"]);
    expect(remembered()[A()]).toBe(2);
    let deltas = 0;
    let fulls = 0;
    h.handler = async (path, opts) => {
      // The rolled-back state, whatever is asked: the own write is gone again, the vault's number below it.
      if (path.startsWith("/sync?since=")) {
        deltas++;
        return { ...old, revision: w.revision + 5, cursor: "c999", delta: true, deleted: [], reset: [A()] };
      }
      if (path === "/sync") {
        fulls++;
        return { ...old, revision: w.revision + 5, cursor: "c999" };
      }
      return handle(path, opts);
    };
    await syncNow();
    await settled();
    // Two more fetches of the whole account, then the answer counts as the server's: checked, and it is a rollback.
    expect([deltas, fulls]).toEqual([1, 2]);
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(remembered()[A()]).toBe(2);
    // Nothing is written on the rolled-back branch: no second valid version 2 ever leaves this device.
    w.calls = [];
    await expect(createItem(A(), login("Other"))).rejects.toThrow(MANIFEST_HELD);
    expect(calls((c) => c.method !== "GET")).toEqual([]);
    // The reviewer's second half: the server really is at the old state, and stays there.
    const shop = [...w.items.values()].find((r) => !["item-1", "item-2"].includes(r.id))!;
    w.items.delete(shop.id);
    const oldRow = (old.vaults as { id: string; manifest: string; manifest_seq: number; manifest_prev: string }[]).find((x) => x.id === A())!;
    Object.assign(w.vaults.get(A())!, { manifest: oldRow.manifest, manifestSeq: oldRow.manifest_seq, manifestPrev: oldRow.manifest_prev });
    h.handler = handle;
    await expect(createItem(A(), login("Other"))).rejects.toThrow(MANIFEST_HELD);
    lock();
    await signIn();
    await syncNow();
    await settled();
    // After a lock, a fresh sign-in and a full sync the device still knows: it saw version 2, the server shows 1.
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(names()).toEqual(["Bank", "Mail"]);
    expect(remembered()[A()]).toBe(2);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 1 });
  });

  it("the reviewer's exact answers (a rolled-back delta, then only answers older than what is shown): what is shown never goes back", async () => {
    await signIn();
    const old = (await handle("/sync", {})) as Record<string, unknown>;
    await createItem(A(), login("Shop"));
    let n = 0;
    h.handler = async (path, opts) => {
      if (path.startsWith("/sync?since=")) {
        n++;
        if (n === 1) return { ...old, revision: w.revision + 5, cursor: "c999", delta: true, deleted: [], reset: [A()] };
        return { ...old, revision: 1, delta: true, deleted: [], reset: [] };
      }
      return handle(path, opts);
    };
    await syncNow();
    await settled();
    await syncNow();
    await settled();
    // The behind delta was not taken over; the honest full answer that followed was.
    expect(names()).toEqual(["Bank", "Mail", "Shop"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(getState().warnings).toEqual([]);
    expect(remembered()[A()]).toBe(2);
  });

  it("a harmless one (an own write while a sync was on its way) costs one fetch of the whole account and no warning", async () => {
    await signIn();
    const stale = handle("/sync?since=c" + w.clock, {});
    await createItem(A(), login("Shop"));
    let served = false;
    h.handler = async (path, opts) => {
      if (path.startsWith("/sync?since=") && !served) {
        served = true;
        w.calls.push({ method: "GET", path, body: undefined });
        return stale;
      }
      return handle(path, opts);
    };
    w.calls = [];
    await syncNow();
    await settled();
    expect(fullSyncs()).toHaveLength(1);
    expect(names()).toEqual(["Bank", "Mail", "Shop"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });
});

describe("the chain of manifests (review 3 / core H1: fork, then join)", () => {
  it("remembers version and link of what it checked and of every manifest it wrote itself", async () => {
    newWorld({ ok: true });
    await signIn();
    const same = () => expect(rememberedLinks()[A()]).toBe(serverCheck(A()).link);
    same();
    const id = await createItem(A(), login("Shop"));
    same();
    await updateItem(entry("Shop"), { ...entry("Shop").item, name: "Shop 2" });
    same();
    await trashItem(id);
    same();
    await restoreItem(id);
    same();
    await importItems(A(), [login("One"), login("Two")]);
    same();
    await rotateVaultKey(A());
    same();
    await updateItem(entry("Shop 2"), entry("Shop 2").item, B);
    same();
    expect(rememberedLinks()[B]).toBe(serverCheck(B).link);
    await purgeItem(id);
    expect(rememberedLinks()[B]).toBe(serverCheck(B).link);
    expect(logCalls()).toEqual([]);
    expect(getState().vaults.some((x) => x.manifestWarning)).toBe(false);
    // Every write named the manifest it replaced.
    for (const c of w.calls) for (const m of ((c.body as { manifests?: Entry[] } | undefined)?.manifests ?? [])) expect(m.prev, c.path).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("another manifest at the version this device wrote itself: warning, also when its items are consistent", async () => {
    await signIn();
    const backup = saveWorld();
    await createItem(A(), login("Shop"));
    expect(remembered()[A()]).toBe(2);
    // The server kept showing another device version 1; that device wrote, making a second valid version 2.
    serveBranch(backup, () => otherCreates(A(), "Other"));
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 2 });
    w.calls = [];
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBe(true);
    // The delta's verdict got one fetch of the whole account before the warning was shown.
    expect(fullSyncs()).toHaveLength(1);
    expect(remembered()[A()]).toBe(2);
    expect(rememberedLinks()[A()]).not.toBe(serverCheck(A()).link);
    await expect(createItem(A(), login("More"))).rejects.toThrow(MANIFEST_HELD);
  });

  it("the other branch at a later version: the manifest log is fetched, doesn't lead back to what this device saw, warning", async () => {
    await signIn();
    const atFirst = storage.get(manifestsKey(SCOPE()))!;
    const backup = saveWorld();
    await createItem(A(), login("Shop"));
    serveBranch(backup, () => {
      otherCreates(A(), "Other 1");
      otherCreates(A(), "Other 2");
      otherCreates(A(), "Other 3");
    });
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 4 });
    w.calls = [];
    await syncNow();
    await settled();
    expect(logCalls().map((c) => c.path)).toContain(`/vaults/${A()}/manifest-log?after=2`);
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(remembered()[A()]).toBe(2);
    // A device that only ever saw version 1 follows that branch without a warning (it is on its history).
    lock();
    storage.set(manifestsKey(SCOPE()), atFirst);
    w.calls = [];
    await boot();
    const a = v.accounts.find((x) => x.name === "alice")!;
    await restoreUnlocked(a.id, unb64(a.sessionBytes));
    await settled();
    expect(logCalls().map((c) => c.path)).toContain(`/vaults/${A()}/manifest-log?after=1`);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(4);
  });

  it("an honest jump of several versions (other devices wrote meanwhile): the log connects, no warning, the newest is remembered", async () => {
    await signIn();
    await createItem(A(), login("Shop"));
    for (let n = 0; n < 5; n++) otherCreates(A(), `Other ${n}`);
    w.logPage = 2;
    w.calls = [];
    await syncNow();
    await settled();
    // Paged: after=2, then after the last entry of each page.
    expect(logCalls().map((c) => c.path.split("after=")[1])).toEqual(["2", "4", "6"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(7);
    expect(rememberedLinks()[A()]).toBe(serverCheck(A()).link);
    expect(fullSyncs()).toEqual([]);
    // One step ahead needs no log.
    otherCreates(A(), "One more");
    w.calls = [];
    await syncNow();
    expect(logCalls()).toEqual([]);
    expect(remembered()[A()]).toBe(8);
  });

  it("a log that needs more than five requests doesn't connect", async () => {
    await signIn();
    for (let n = 0; n < 13; n++) otherCreates(A(), `Other ${n}`);
    w.logPage = 2;
    w.calls = [];
    await syncNow();
    await settled();
    expect(logCalls().length).toBe(10);
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(remembered()[A()]).toBe(1);
  });

  it("while the log can't be fetched the answer is not taken over: old copy, old verdict, no warning, writes wait; then 404 is a mismatch", async () => {
    await signIn();
    for (let n = 0; n < 3; n++) otherCreates(A(), `Other ${n}`);
    const failing = (status: number) => async (path: string, opts: Opts) => {
      if (path.includes("/manifest-log")) {
        w.calls.push({ method: "GET", path, body: undefined });
        throw status === 0 ? new UnreachableError() : err(status, status === 404 ? "not_found" : "unavailable");
      }
      return handle(path, opts);
    };
    for (const status of [0, 503, 429]) {
      h.handler = failing(status);
      w.calls = [];
      await expect(syncNow()).rejects.toThrow();
      await settled();
      expect(logCalls(), String(status)).toHaveLength(1);
      // Nothing of the answer is shown or kept.
      expect(names()).toEqual(["Bank", "Mail"]);
      expect(vaultState(A()).manifestWarning).toBeUndefined();
      expect(getState().warnings).toEqual([]);
      expect(remembered()[A()]).toBe(1);
      // Writes into that vault wait for a sync that checks it (and fail with it), nothing is sent.
      w.calls = [];
      await expect(createItem(A(), login("Shop"))).rejects.toThrow();
      await expect(trashItem("item-1")).rejects.toThrow();
      expect(calls((c) => c.method !== "GET")).toEqual([]);
    }
    // The other vault is not held up.
    await createItem(B, login("Elsewhere"));
    expect(names()).toContain("Elsewhere");
    // The next sync asks again (the same cursor), and with the log the answer is taken over.
    h.handler = handle;
    await syncNow();
    expect(names()).toEqual(["Bank", "Elsewhere", "Mail", "Other 0", "Other 1", "Other 2"]);
    expect(remembered()[A()]).toBe(4);
    await createItem(A(), login("Shop"));
    // A server that says "no such log" (or "bad request") has answered: the vault is a mismatch.
    for (const status of [404, 400]) {
      for (let n = 0; n < 2; n++) otherCreates(A(), `More ${status} ${n}`);
      h.handler = failing(status);
      await syncNow();
      await settled();
      expect(vaultState(A()).manifestWarning, String(status)).toBe(true);
      h.handler = handle;
      await syncNow();
      expect(vaultState(A()).manifestWarning).toBeUndefined();
    }
  });

  it("a log answer that is no log, or that never ends, is a mismatch; garbage entries are not trusted", async () => {
    await signIn();
    for (const answer of [null, {}, { entries: "x" }, { entries: [], more: true }, { entries: [{ seq: "2", prev: 5 }, null, 7] }]) {
      for (let n = 0; n < 2; n++) otherCreates(A(), `Other ${JSON.stringify(answer)} ${n}`);
      h.handler = async (path, opts) => (path.includes("/manifest-log") ? answer : handle(path, opts));
      await syncNow();
      await settled();
      expect(vaultState(A()).manifestWarning, JSON.stringify(answer)).toBe(true);
      h.handler = handle;
      await syncNow();
      expect(vaultState(A()).manifestWarning).toBeUndefined();
    }
  });

  it("the chain crosses a key replacement and a new baseline", async () => {
    await signIn();
    const key = manifestsKey(SCOPE());
    const atFirst = storage.get(key)!;
    const again = async () => {
      lock();
      await signIn();
    };
    // Another device writes, this one replaces the key (a whole new manifest under the new key), others write on.
    otherCreates(A(), "One");
    await rotateVaultKey(A());
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: 3 });
    expect(rememberedLinks()[A()]).toBe(serverCheck(A()).link);
    expect(lastBody((c) => c.path.endsWith("/rotate")).manifests![0].prev).toBe(w.vaults.get(A())!.log[2].prev);
    otherCreates(A(), "Two");
    otherCreates(A(), "Three");
    await syncNow();
    expect(remembered()[A()]).toBe(5);
    const atFifth = storage.get(key)!;
    // A device that last saw the manifest from before the key replacement follows by the log (hashes alone).
    storage.set(key, atFirst);
    w.calls = [];
    await again();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(5);
    // A baseline ("Use the server's copy") names the manifest it replaces...
    tamper(() => {
      w.items.delete("item-2");
      w.tombs.push({ id: "item-2", vault_id: A(), at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    const shown = w.vaults.get(A())!;
    const replaced = core.manifestLink(shown.manifestSeq, shown.manifestPrev!, shown.manifest!);
    await acceptServerCopy(A());
    expect(lastBody((c) => c.path === `/vaults/${A()}/manifest`)).toMatchObject({ base_seq: 5, seq: 6, prev: replaced });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(rememberedLinks()[A()]).toBe(serverCheck(A()).link);
    otherCreates(A(), "Four");
    // ...so a device on the history under it accepts it, through the log.
    storage.set(key, atFifth);
    await again();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(remembered()[A()]).toBe(7);
    // And one that remembers a state on another history (here: a link nobody ever stored) keeps its warning.
    storage.set(key, JSON.stringify({ [A()]: { version: 4, link: "B".repeat(43) } }));
    await again();
    expect(vaultState(A()).manifestWarning).toBe(true);
  });
});

describe("an item can't be hidden under a manifest that checks out (review 4)", () => {
  it("a row whose item key was broken: the vault shows its warning and takes no writes; a new record can't clear it", async () => {
    await signIn();
    const good = w.items.get("item-1")!.item_key;
    tamper(() => {
      // The manifest doesn't cover `item_key`: the server's own check still says "ok".
      w.items.set("item-1", { ...w.items.get("item-1")!, item_key: w.items.get("item-2")!.item_key, at: w.clock });
      return A();
    });
    expect(serverCheck(A())).toMatchObject({ status: "ok" });
    w.calls = [];
    await syncNow();
    await settled();
    expect(names()).toEqual(["Bank"]);
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(vaultState(B).manifestWarning).toBeUndefined();
    // One fetch of the whole account before the warning; nothing remembered beyond what was.
    expect(fullSyncs()).toHaveLength(1);
    expect(remembered()[A()]).toBe(1);
    w.calls = [];
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_HELD);
    await expect(trashItem("item-2")).rejects.toThrow(MANIFEST_HELD);
    await expect(rotateVaultKey(A())).rejects.toThrow(MANIFEST_HELD);
    await expect(acceptServerCopy(A())).rejects.toThrow(MANIFEST_HIDDEN);
    expect(calls((c) => c.method !== "GET")).toEqual([]);
    // Lock and unlock: still told.
    lock();
    await signIn();
    expect(vaultState(A()).manifestWarning).toBe(true);
    // The row as it was: the warning clears by itself.
    tamper(() => {
      w.items.set("item-1", { ...w.items.get("item-1")!, item_key: good, at: w.clock });
      return A();
    });
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(names()).toEqual(["Bank", "Mail"]);
    await createItem(A(), login("Shop"));
  });

  it("a row sent without its data but with its correct hash: the web vault asked for whole rows, so the vault keeps its warning", async () => {
    await signIn();
    const real = handle;
    h.handler = async (path, opts) => {
      const answer = (await real(path, opts)) as { items?: Record<string, unknown>[] };
      if (!path.startsWith("/sync") || !Array.isArray(answer?.items)) return answer;
      return {
        ...answer,
        items: answer.items.map((r) => {
          if (r.id !== "item-1") return r;
          const { data, ...rest } = r;
          return { ...rest, data_sha256: core.manifestDataHash(data as string) };
        }),
      };
    };
    tamper(() => {
      w.items.set("item-1", { ...w.items.get("item-1")!, at: w.clock });
      return A();
    });
    await syncNow();
    await settled();
    expect(names()).toEqual(["Bank"]);
    expect(vaultState(A()).manifestWarning).toBe(true);
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_HELD);
  });

  it("a row carrying a device-private marker (`served_sha256`) with other data is a mismatch: nothing on a row is taken from the server (R2)", async () => {
    await signIn();
    const older = { ...w.items.get("item-1")! };
    await updateItem(entry("Mail"), { ...entry("Mail").item, name: "Mail 2" });
    const current = w.items.get("item-1")!;
    // The server serves the older data and claims, on the row, the hash of the current one.
    tamper(() => {
      w.items.set("item-1", { ...current, item_key: older.item_key, data: older.data, at: w.clock, ...({ served_sha256: core.manifestDataHash(current.data), data_sha256: core.manifestDataHash(current.data) } as object) });
      return A();
    });
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBe(true);
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_HELD);
  });
});

describe("the trash state is `deleted_at` not null, for the app as for the core (core M2)", () => {
  it("a trashed item served with `deleted_at: 0` is never shown as live: the vault is a mismatch and the item stays in the trash", async () => {
    await signIn();
    await trashItem("item-1");
    expect(entry("Mail").deletedAt).not.toBeNull();
    tamper(() => {
      w.items.set("item-1", { ...w.items.get("item-1")!, deleted_at: 0, at: w.clock });
      return A();
    });
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBe(true);
    // Whatever shows it: not live (`deletedAt !== null` is the rule every page goes by).
    expect(entry("Mail").deletedAt).toBe(0);
    expect(entry("Mail").deletedAt !== null).toBe(true);
    await expect(restoreItem("item-1")).rejects.toThrow(MANIFEST_HELD);
  });

  it("a number the app can't count with (a fraction, a negative, too large) makes the whole answer invalid: nothing of it is used (R12)", async () => {
    await signIn();
    const real = handle;
    for (const change of [
      (a: { vaults: Record<string, unknown>[] }) => (a.vaults[0].manifest_seq = 1.5),
      (a: { vaults: Record<string, unknown>[] }) => (a.vaults[0].seq = -1),
      (a: { vaults: Record<string, unknown>[] }) => (a.vaults[0].key_epoch = 2 ** 53),
      (a: { items: Record<string, unknown>[] }) => (a.items[0].deleted_at = 0.5),
      (a: { items: Record<string, unknown>[] }) => (a.items[0].deleted_at = "1"),
    ]) {
      otherCreates(A(), `New ${change.toString().length}`);
      h.handler = async (path, opts) => {
        const answer = (await real(path, opts)) as { vaults: Record<string, unknown>[]; items: Record<string, unknown>[] };
        if (path.startsWith("/sync") && path !== "/sync/revision") change(answer as never);
        return answer;
      };
      const before = names();
      await expect(syncNow()).rejects.toThrow("unexpected response");
      expect(names()).toEqual(before);
      expect(vaultState(A()).manifestWarning).toBeUndefined();
      h.handler = real;
      await syncNow();
    }
    expect(names().length).toBe(7);
  });
});

describe("warnings come from the server's answer, not from this app's bookkeeping (R4, review 8)", () => {
  it("two tabs: an answer read before the other tab's write is not a rollback (one fetch of the whole account, no warning)", async () => {
    await signIn();
    // This tab's sync is on its way: the answer was read before the other tab's write...
    const early = await handle(`/sync?since=c${w.clock}`, {});
    // ...which the other tab then made and remembered (the memory is shared by the tabs).
    otherCreates(A(), "From the other tab");
    const row = w.vaults.get(A())!;
    storage.set(manifestsKey(SCOPE()), JSON.stringify({ ...JSON.parse(storage.get(manifestsKey(SCOPE()))!), [A()]: { version: row.manifestSeq, link: linkOf(row) } }));
    let first = true;
    h.handler = async (path, opts) => {
      if (first && path.startsWith("/sync?since=")) {
        first = false;
        w.calls.push({ method: "GET", path, body: undefined });
        return early;
      }
      return handle(path, opts);
    };
    w.calls = [];
    await syncNow();
    await settled();
    expect(synced().map((c) => c.path.startsWith("/sync?since="))).toEqual([true, false]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(getState().warnings).toEqual([]);
    expect(names()).toEqual(["Bank", "From the other tab", "Mail"]);
  });

  it("when that fetch can't be had, nothing is taken over and no warning is shown", async () => {
    await signIn();
    tamper(() => {
      w.items.delete("item-2");
      w.tombs.push({ id: "item-2", vault_id: A(), at: w.clock });
      return A();
    });
    h.handler = async (path, opts) => {
      if (path === "/sync") throw new UnreachableError();
      return handle(path, opts);
    };
    await expect(syncNow()).rejects.toThrow(UnreachableError);
    expect(names()).toEqual(["Bank", "Mail"]);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    // With the server's whole answer the warning is shown.
    h.handler = handle;
    await syncNow();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(names()).toEqual(["Mail"]);
  });

  it("memory that can't be read is not 'nothing remembered': nothing is checked against it, written over it or started; writes wait", async () => {
    newWorld({ ok: true });
    await signIn();
    expect(remembered()).toEqual({ [A()]: 1, [B]: 1 });
    lock();
    storage.set(manifestsKey(SCOPE()), "{broken");
    // The server takes the chance: no manifest any more (a device with readable memory would call that a rollback).
    for (const x of w.vaults.values()) Object.assign(x, { manifest: null, manifestSeq: 0, manifestPrev: null, manifestOk: true });
    await signIn();
    await syncNow();
    await settled();
    expect(storage.get(manifestsKey(SCOPE()))).toBe("{broken");
    expect(getState().vaults.some((x) => x.manifestWarning)).toBe(false);
    // No first manifest is started over what the server shows, and nothing is written into the unchecked vaults.
    expect(calls((c) => c.path.endsWith("/manifest"))).toEqual([]);
    w.calls = [];
    await expect(createItem(A(), login("Shop"))).rejects.toThrow(MANIFEST_UNCHECKED);
    await expect(trashItem("item-1")).rejects.toThrow(MANIFEST_UNCHECKED);
    await expect(rotateVaultKey(A())).rejects.toThrow(MANIFEST_UNCHECKED);
    expect(calls((c) => c.method !== "GET")).toEqual([]);
    expect(names()).toEqual(["Bank", "Mail"]);
  });
});

describe("a first manifest is never started over a copy the server sent older than this device saw (R9)", () => {
  it("the item keeps its mark across syncs and a lock, and the vault gets no manifest from this device", async () => {
    newWorld();
    await signIn();
    const old = { ...w.items.get("item-1")! };
    await updateItem(entry("Mail"), { ...entry("Mail").item, name: "Mail 2" });
    tamper(() => {
      w.items.set("item-1", { ...old, revision: w.items.get("item-1")!.revision + 1, at: w.clock });
      return A();
    });
    await syncNow();
    expect(entry("Mail 2")).toMatchObject({ rollback: true });
    // Every member's apps are ready now: vault B gets its manifest, vault A (which holds the older copy) does not.
    for (const x of w.vaults.values()) x.manifestOk = true;
    tamper(() => B);
    await syncNow();
    await settled();
    expect(w.vaults.get(B)!.manifestSeq).toBe(1);
    expect(w.vaults.get(A())!.manifestSeq).toBe(0);
    // After a lock (nothing newer in memory) the served copy is shown, still marked, still no manifest.
    lock();
    await signIn();
    tamper(() => B);
    await syncNow();
    await settled();
    expect(entry("Mail")).toMatchObject({ rollback: true });
    expect(getState().warnings).toContain(ROLLBACK_SHOWN);
    expect(w.vaults.get(A())!.manifestSeq).toBe(0);
    // Saved over (the user keeps this version): the mark goes, and the vault's first manifest is started.
    await updateItem(entry("Mail"), { ...entry("Mail").item, name: "Mail 3" });
    expect(entry("Mail 3").rollback).toBeUndefined();
    tamper(() => B);
    await syncNow();
    await settled();
    expect(w.vaults.get(A())!.manifestSeq).toBe(1);
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
      Object.assign(w.vaults.get(A())!, { manifest: before.manifest, manifestSeq: before.manifestSeq, manifestPrev: before.manifestPrev });
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
        setManifest(vault, key.manifestNext(A(), vault.epoch, vault.manifestSeq, vault.manifestPrev!, vault.manifest!, [have], [{ ...have, deleted_at: deletedAt }]) as Built);
      }
      bump(A());
      w.items.set(id, { ...have, deleted_at: deletedAt, revision: w.clock * 1000, at: w.clock });
    });
  }

  // The device's clock is the server's in these tests (`later` moves both), except where a test says otherwise.
  let deviceAhead = 0;
  let clock: ReturnType<typeof vi.spyOn> | null = null;
  beforeEach(() => {
    deviceAhead = 0;
    clock = vi.spyOn(Date, "now").mockImplementation(() => (w.serverTime + deviceAhead) * 1000);
  });
  afterEach(() => clock?.mockRestore());
  /** Time passes (server and device), and the app syncs. */
  async function later(days: number) {
    w.serverTime += days * DAY;
    tamper(() => B);
    await syncNow();
    await settled();
  }
  const purges = () => calls((c) => c.path.endsWith("/trash/purge"));
  const trashSeen = (): Record<string, number> => JSON.parse(storage.get(`pa.trash-seen.${SCOPE()}`) ?? "{}");

  it("is deleted by the app once the server's rule says so AND this device itself saw it in the trash that long", async () => {
    const due = otherCreates(A(), "Due");
    const fresh = otherCreates(A(), "Fresh");
    otherTrashes(due, w.serverTime - DAY);
    await signIn();
    // First seen in the trash now, by the device's clock.
    expect(trashSeen()).toEqual({ [due]: w.serverTime });
    await later(10);
    otherTrashes(fresh, w.serverTime);
    await later(0);
    expect(trashSeen()[fresh]).toBe(w.serverTime);
    // Day 29: the server's rule says "due" (30 days in the trash), the device has watched for 29.
    await later(19);
    expect(purges()).toEqual([]);
    const rev = w.items.get(due)!.revision;
    w.calls = [];
    await later(1);
    expect(purges()).toHaveLength(1);
    const seq = w.vaults.get(A())!.manifestSeq;
    expect(purges()[0].body).toMatchObject({ items: [{ id: due, revision: rev }], manifests: [{ vault_id: A(), seq }] });
    expect((purges()[0].body as { manifests: Entry[] }).manifests[0]).not.toHaveProperty("link");
    expect(w.items.has(due)).toBe(false);
    expect(w.items.has(fresh)).toBe(true);
    expect(serverCheck(A())).toMatchObject({ status: "ok", version: seq, live: 2, trashed: 1 });
    expect(names()).toEqual(["Bank", "Fresh", "Mail"]);
    expect(remembered()[A()]).toBe(seq);
    expect(rememberedLinks()[A()]).toBe(serverCheck(A()).link);
    expect(trashSeen()).toEqual({ [fresh]: expect.any(Number) });
    // Shown without asking the server again, and the next sync agrees.
    expect(w.calls.at(-1)!.path).toBe(`/vaults/${A()}/trash/purge`);
    w.calls = [];
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(purges()).toEqual([]);
  });

  it("the server's word alone never empties a trash: its clock, its retention and `deleted_at` are not enough (review 9)", async () => {
    const id = otherCreates(A(), "Trashed today");
    otherTrashes(id, w.serverTime);
    await signIn();
    // A `deleted_at` long past (rewritten the right way, so the manifest still checks out): the device saw it today.
    otherTrashes(id, 5);
    await later(0);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
    expect(purges()).toEqual([]);
    // A server clock far in the future, or 31 days ahead of the device's: nothing.
    const real = w.serverTime;
    for (const claimed of [Number.MAX_SAFE_INTEGER, real + 31 * DAY]) {
      deviceAhead = real - claimed;
      w.serverTime = claimed;
      tamper(() => B);
      await syncNow();
      await settled();
    }
    expect(purges()).toEqual([]);
    w.serverTime = real;
    deviceAhead = 0;
    // The shortest retention: still only after the device watched a day.
    w.trashDays = 1;
    await later(0);
    expect(purges()).toEqual([]);
    expect(w.items.has(id)).toBe(true);
    await later(1);
    expect(purges()).toHaveLength(1);
    expect(w.items.has(id)).toBe(false);
  });

  it("an item taken out of the trash and put back is watched afresh", async () => {
    const id = otherCreates(A(), "Back and forth");
    otherTrashes(id, w.serverTime);
    await signIn();
    await later(29);
    await restoreItem(id);
    expect(trashSeen()).toEqual({});
    otherTrashes(id, 5);
    await later(2);
    expect(purges()).toEqual([]);
    expect(w.items.has(id)).toBe(true);
  });

  it("one attempt: a refusal is ignored and nothing is retried until the next sync", async () => {
    const due = otherCreates(A(), "Due");
    otherTrashes(due, w.serverTime);
    await signIn();
    w.next.push({
      path: `/vaults/${A()}/trash/purge`,
      run: () => {
        throw err(409, "manifest_conflict");
      },
    });
    await later(31);
    expect(purges()).toHaveLength(1);
    expect(w.items.has(due)).toBe(true);
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("one request of at most the server's limit for each sync answer, each with its own next manifest", async () => {
    for (let n = 0; n < 5; n++) otherTrashes(otherCreates(A(), `Due ${n}`), w.serverTime);
    await signIn();
    h.config = { features: [...FEATURES], limits: { max_import_items: 2 } };
    const first = w.vaults.get(A())!.manifestSeq;
    await later(31);
    expect(purges().map((c) => (c.body as { items: unknown[] }).items.length)).toEqual([2]);
    await later(0);
    await later(0);
    await later(0);
    const sent = purges().map((c) => c.body as { items: unknown[]; manifests: Entry[] });
    expect(sent.map((p) => p.items.length)).toEqual([2, 2, 1]);
    expect(sent.map((p) => p.manifests[0].seq)).toEqual([first + 1, first + 2, first + 3]);
    expect(serverCheck(A())).toMatchObject({ status: "ok", live: 2, trashed: 0 });
    expect(vaultState(A()).manifestWarning).toBeUndefined();
  });

  it("never in a vault without a manifest (the server sweeps it), with a server that keeps the trash forever, or as a reader", async () => {
    newWorld();
    otherTrashes("item-1", w.serverTime);
    await signIn();
    await later(31);
    expect(purges()).toEqual([]);

    newWorld({ manifests: true });
    otherTrashes("item-1", w.serverTime);
    w.trashDays = 0;
    await signIn();
    await later(31);
    expect(w.items.has("item-1")).toBe(true);
    w.trashDays = 30;
    w.vaults.get(A())!.role = "read";
    await later(1);
    expect(w.items.has("item-1")).toBe(true);
    expect(purges()).toEqual([]);
    // (As a writer it goes: the two cases above held it back, nothing else.)
    w.vaults.get(A())!.role = "owner";
    await later(0);
    expect(w.items.has("item-1")).toBe(false);
  });

  it("never in a vault that doesn't check out", async () => {
    otherTrashes("item-1", w.serverTime);
    await signIn();
    w.serverTime += 31 * DAY;
    tamper(() => {
      w.items.set("item-2", { ...w.items.get("item-2")!, data: w.items.get("item-1")!.data, at: w.clock });
      return A();
    });
    await syncNow();
    await settled();
    expect(vaultState(A()).manifestWarning).toBe(true);
    expect(w.items.has("item-1")).toBe(true);
    expect(purges()).toEqual([]);
  });
});
