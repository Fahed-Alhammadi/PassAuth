/**
 * A tiny in-memory PassAuth server for background tests (API contract v2 where
 * `features` says so, the older behaviour otherwise). Install its `fetch` with
 * vi.stubGlobal("fetch", server.fetch). Every request is recorded.
 *
 * With `delta_sync` in `features` it also speaks delta sync like the real one
 * (crates/server/src/vault/sync.rs): every vault has a `seq` that each write
 * into it raises, /sync answers a `cursor` (here: base64 JSON of each vault's
 * seq and key epoch), `?since=` answers only what changed (`deleted`, `reset`,
 * `delta: true`), `trash=summary` leaves trashed items' key and data out,
 * /sync/revision lists the vault numbers and writes answer `vault_seq`.
 */

export interface Recorded {
  method: string;
  path: string;
  /** The query string's parameters. */
  query: Record<string, string>;
  headers: Record<string, string>;
  body: any;
}

export interface ServerVault {
  id: string;
  wrapped_key: string;
  key_kind: "account" | "sealed";
  role: "owner" | "admin" | "write" | "read";
  meta: string;
  key_epoch: number;
  /** Delta sync: raised by every write into the vault. */
  seq?: number;
}

export interface ServerItem {
  id: string;
  vault_id: string;
  item_key: string;
  data: string;
  revision: number;
  deleted_at: number | null;
  /** Delta sync: the vault's number when the item was written last. */
  seq?: number;
}

type Reply = { status?: number; body?: unknown; headers?: Record<string, string> };
type Handler = (req: Recorded) => Reply | undefined;

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? "" : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

export function fakeServer(base = "https://vault.test") {
  const s = {
    base,
    requests: [] as Recorded[],
    features: ["key_epoch", "idempotent_create", "error_codes", "revoke_others", "trash_retention"] as string[],
    revision: 1,
    bundle: { account_id: "acc-1", password: "pw", secret_key_enabled: false } as Record<string, unknown>,
    vaults: [{ id: "v-own", wrapped_key: "own-1", key_kind: "account", role: "owner", meta: JSON.stringify({ name: "Personal" }), key_epoch: 1 }] as ServerVault[],
    items: [] as ServerItem[],
    /** Delta sync: items deleted for good or moved out of a vault, with the vault's number then. */
    tombstones: [] as { id: string; vault_id: string; seq: number }[],
    /** Vaults shared with the account and not accepted yet (listed in every /sync). */
    invitations: [] as Record<string, unknown>[],
    user: { id: "u-1", email: "alex@example.com", name: "Alex", email_verified: true },
    /** Per-route overrides, by "METHOD /path" (path without /api); return undefined to fall through. */
    handlers: {} as Record<string, Handler>,
    /** Answer the next request to this route with a network failure after it was applied (a timeout the server saw through). */
    dropReply: new Set<string>(),

    /** Raise vault `vaultId`'s number for a write (delta sync) and return it. */
    bump(vaultId: string): number {
      const v = s.vaults.find((x) => x.id === vaultId);
      if (!v) return 0;
      v.seq = (v.seq ?? 0) + 1;
      return v.seq;
    },

    /** Replace a vault's key, as removing a member does: new epoch, new wrapped key, every item re-encrypted under it. */
    rotate(vaultId: string) {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      v.key_epoch++;
      v.wrapped_key = `${vaultId}-key-${v.key_epoch}`;
      s.revision++;
      const seq = s.bump(vaultId);
      for (const i of s.items) {
        if (i.vault_id !== vaultId) continue;
        i.item_key = `${v.wrapped_key}:rot-${i.id}`;
        i.revision = s.revision;
        i.seq = seq;
      }
    },

    /** Another device edits an item (same key). */
    editElsewhere(id: string, patch: Record<string, unknown>) {
      const i = s.items.find((x) => x.id === id)!;
      i.data = JSON.stringify({ ...JSON.parse(i.data), ...patch });
      i.revision = ++s.revision;
      i.seq = s.bump(i.vault_id);
    },

    /** Another device adds an item (encrypted under the vault's current key, like the fake core does). */
    addElsewhere(id: string, vaultId: string, data: string) {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      s.items.push({ id, vault_id: vaultId, item_key: `${v.wrapped_key}:${id}`, data, revision: ++s.revision, deleted_at: null, seq: s.bump(vaultId) });
    },

    /** Another device deletes an item for good. */
    deleteElsewhere(id: string) {
      const i = s.items.find((x) => x.id === id)!;
      s.items = s.items.filter((x) => x !== i);
      s.revision++;
      s.tombstones.push({ id, vault_id: i.vault_id, seq: s.bump(i.vault_id) });
    },

    /** The cursor of an answer: each vault's number and key epoch now. */
    cursor(): string {
      return btoa(JSON.stringify(Object.fromEntries(s.vaults.map((v) => [v.id, [v.seq ?? 0, v.key_epoch]]))));
    },

    fetch: async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (url.origin !== base) throw new TypeError("Failed to fetch");
      const headers: Record<string, string> = {};
      new Headers(init.headers).forEach((v, k) => {
        headers[k] = v;
      });
      const req: Recorded = {
        method: init.method ?? "GET",
        path: url.pathname.replace(/^\/api/, ""),
        query: Object.fromEntries(url.searchParams),
        headers,
        body: init.body ? JSON.parse(String(init.body)) : undefined,
      };
      s.requests.push(req);
      const route = `${req.method} ${req.path.replace(/\/items\/[^/]+$/, "/items/:id")}`;
      const custom = s.handlers[route]?.(req);
      const reply = custom ?? s.route(req);
      if (s.dropReply.delete(route)) throw new TypeError("Failed to fetch");
      return json(reply.status ?? 200, reply.body, reply.headers);
    },

    syncAnswer: (query: Record<string, string>) => syncAnswer(s, query),

    route(req: Recorded): Reply {
      const v2 = (f: string) => s.features.includes(f);
      const epochChanged = (vaultId: string, epoch: unknown) => {
        const v = s.vaults.find((x) => x.id === vaultId);
        return v2("key_epoch") && epoch !== undefined && v !== undefined && epoch !== v.key_epoch;
      };
      const keyChanged = { status: 409, body: { error: "vault_key_changed", message: "the vault key was replaced; sync and try again" } };
      if (req.method === "GET" && req.path === "/config") return { body: { name: "PassAuth", version: "0.10.0", ...(s.features.length ? { api: 2, features: s.features } : {}) } };
      if (req.method === "GET" && req.path === "/sync") return { body: s.syncAnswer(req.query) };
      if (req.method === "GET" && req.path === "/sync/revision") {
        return { body: { revision: s.revision, ...(v2("delta_sync") ? { vaults: Object.fromEntries(s.vaults.map((v) => [v.id, v.seq ?? 0])) } : {}) } };
      }
      if (req.method === "DELETE" && req.path.startsWith("/items/")) {
        const i = s.items.find((x) => x.id === req.path.slice("/items/".length));
        if (!i) return { status: 404, body: { error: "not_found", message: "not found" } };
        i.deleted_at = Math.floor(Date.now() / 1000);
        i.revision = ++s.revision;
        i.seq = s.bump(i.vault_id);
        return { body: { revision: i.revision, ...(v2("delta_sync") ? { vault_seq: i.seq } : {}) } };
      }
      if (req.method === "POST" && req.path === "/items") {
        const b = req.body;
        if (epochChanged(b.vault_id, b.key_epoch)) return keyChanged;
        const existing = s.items.find((i) => i.id === b.id);
        if (existing) {
          if (v2("idempotent_create") && existing.vault_id === b.vault_id && existing.item_key === b.key && existing.data === b.data) {
            return { body: { id: b.id, revision: existing.revision } };
          }
          return v2("error_codes")
            ? { status: 409, body: { error: "item_exists", message: "item id already exists" } }
            : { status: 409, body: { error: "conflict", message: "item id already exists" } };
        }
        s.items.push({ id: b.id, vault_id: b.vault_id, item_key: b.key, data: b.data, revision: ++s.revision, deleted_at: null, seq: s.bump(b.vault_id) });
        return { body: { id: b.id, revision: s.revision, ...(v2("delta_sync") ? { vault_seq: s.vaults.find((v) => v.id === b.vault_id)?.seq } : {}) } };
      }
      if (req.method === "PUT" && req.path.startsWith("/items/")) {
        const b = req.body;
        const i = s.items.find((x) => x.id === b.id);
        if (!i) return { status: 404, body: { error: "not_found", message: "not found" } };
        if (epochChanged(b.vault_id, b.key_epoch)) return keyChanged;
        if (b.revision !== undefined && b.revision !== i.revision) {
          return v2("error_codes")
            ? { status: 409, body: { error: "revision_conflict", message: "item changed on another device; sync and retry" } }
            : { status: 409, body: { error: "conflict", message: "item changed on another device; sync and retry" } };
        }
        Object.assign(i, { vault_id: b.vault_id, item_key: b.key, data: b.data, revision: ++s.revision, seq: s.bump(b.vault_id) });
        return { body: { id: i.id, revision: s.revision, ...(v2("delta_sync") ? { vault_seq: i.seq } : {}) } };
      }
      if (req.method === "POST" && req.path === "/auth/logout") return { body: {} };
      if (req.method === "GET" && req.path === "/account") return { body: { email: s.user.email, two_factor: [], passkeys: [], policy_violations: [] } };
      if (req.method === "POST" && req.path === "/auth/refresh") return { status: 401, body: { error: "unauthorized", message: "authentication required" } };
      return { status: 404, body: { error: "not_found", message: "not found" } };
    },
  };
  return s;
}

export type FakeServer = ReturnType<typeof fakeServer>;

type Server = FakeServer;

/** GET /sync: the whole account, or with `since` only what changed (servers with `delta_sync`). */
function syncAnswer(s: Server, query: Record<string, string>) {
  const delta = s.features.includes("delta_sync");
  const summary = delta && query.trash === "summary";
  const row = (i: ServerItem) => {
    const { seq: _seq, ...rest } = i;
    return summary && i.deleted_at ? { ...rest, item_key: undefined, data: undefined } : rest;
  };
  const vaults = s.vaults.map((v) => {
    const { seq, ...rest } = v;
    return { ...rest, ...(s.features.includes("key_epoch") ? {} : { key_epoch: undefined }), ...(delta ? { seq: seq ?? 0 } : {}) };
  });
  const base = { revision: s.revision, user: s.user, bundle: s.bundle, vaults, invitations: s.invitations };
  if (!delta) return { ...base, items: s.items.map(row) };
  let since: Record<string, [number, number]> | null = null;
  try {
    since = query.since ? JSON.parse(atob(query.since)) : null;
  } catch {
    since = null; // an unreadable cursor gets the full answer, never an error
  }
  if (!since) return { ...base, cursor: s.cursor(), items: s.items.map(row) };
  const reset = s.vaults.filter((v) => !since[v.id] || since[v.id]![1] !== v.key_epoch || since[v.id]![0] > (v.seq ?? 0)).map((v) => v.id);
  const after = (vaultId: string, seq: number | undefined) => (seq ?? 0) > (since[vaultId]?.[0] ?? 0);
  return {
    ...base,
    cursor: s.cursor(),
    items: s.items.filter((i) => reset.includes(i.vault_id) || after(i.vault_id, i.seq)).map(row),
    deleted: s.tombstones.filter((t) => !reset.includes(t.vault_id) && after(t.vault_id, t.seq)).map(({ id, vault_id }) => ({ id, vault_id })),
    reset,
    delta: true,
  };
}

/** An account record as storage.ts keeps it, signed in to `server`. */
export const accountRecord = (server = "https://vault.test", email = "alex@example.com") => ({
  server,
  email,
  name: "",
  tokens: { access: "access-1", refresh: "refresh-1" },
  lastSync: 0,
  persistedKeys: null,
});

/** Session keys (storage.ts SessionData) that the fake core restores. */
export const sessionKeys = (bundle: unknown = { account_id: "acc-1", password: "pw", secret_key_enabled: false }) => ({ accountId: "acc-1", keys: "AQID", bundle });
