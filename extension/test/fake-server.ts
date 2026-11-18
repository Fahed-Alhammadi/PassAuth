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
 *
 * `/api/config` always lists `signed_sharing` (every server this app talks to has it) unless `outdated` says
 * otherwise. With `vault_manifest` in `features` it keeps vault manifests like the real one
 * (crates/server/src/vault/manifest.rs): vault rows carry `manifest`, `manifest_seq`, `manifest_prev`, `manifest_ok`,
 * answers carry `server_time` and `trash_days`, trash summaries carry `data_sha256`, every item write into a vault
 * with a manifest must bring the next one, which must name the vault's current one as its predecessor (400
 * `manifest_required`; 409 `manifest_conflict` for another version or another `prev`; 400 for a `prev` that is no
 * link), `PUT /vaults/{id}/manifest` starts one or writes a baseline (always exactly one version above the vault's:
 * anything else is 400), `POST /vaults/{id}/trash/purge` deletes trashed items for good, every write answer names the
 * vault's manifest after it (`manifest_seq` and `manifest_link`; a create sent again is answered as a repeat, with the
 * manifest the server holds), and
 * `GET /vaults/{id}/manifest-log?after=` lists every manifest stored (`{seq, prev, digest}`, `logPage` an answer). A manifest a client sends is checked with the real
 * core against the items the server then holds (test/manifest-key.ts): one that doesn't describe them is listed in
 * `manifestErrors` and answered 500. Writes "elsewhere" (the helpers below) bring their own manifest, like another device.
 */
import { dataHash, manifestKey, manifestLink, ZERO_LINK } from "./manifest-key";

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
  /** Vault manifests: the sealed manifest and its version (0 / absent: none), and the gate for a first one. */
  manifest?: string | null;
  manifest_seq?: number;
  /** The link of the manifest the current one replaced (null: the vault has none). */
  manifest_prev?: string | null;
  manifest_ok?: boolean;
}

/** A manifest a write carries. */
interface SentManifest {
  vault_id: string;
  seq: number;
  prev?: unknown;
  sealed: string;
}

/** An entry of a vault's manifest log. */
export interface LogEntry {
  seq: number;
  prev: string;
  digest: string;
}

const LINK = /^[A-Za-z0-9_-]{43}$/;

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

/**
 * What new fake servers start with. `identity`: the signing identity `/sync` lists for the account (signed sharing).
 * None by default (the real core then makes and uploads one, as signed-sharing.test.ts tests); test/fake-core.ts sets
 * one its stand-in account opens, so tests about other things see no identity upload.
 */
export const defaults = { identity: null as unknown };

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
    user: { id: "u-1", email: "alex@example.com", name: "Alex", email_verified: true, ...(defaults.identity ? { identity: defaults.identity } : {}) } as {
      id: string;
      email: string;
      name: string;
      email_verified: boolean;
      identity?: unknown;
    },
    /** Per-route overrides, by "METHOD /path" (path without /api); return undefined to fall through. */
    handlers: {} as Record<string, Handler>,
    /** Answer the next request to this route with a network failure after it was applied (a timeout the server saw through). */
    dropReply: new Set<string>(),
    /** `/api/config`: "old" = a server from before API 2 (no `api`, no `features`); "unsigned" = API 2 without `signed_sharing`. */
    outdated: null as null | "old" | "unsigned",
    /** Vault manifests: the admin's trash setting (0: keep forever) and the server's clock (null: the real one). */
    trashDays: 0,
    now: null as number | null,
    /** `/api/config` `limits`. */
    limits: {} as Record<string, number>,
    /** Trash summaries without `data_sha256` (a server that leaves them out). */
    omitHashes: false,
    /** Manifests clients sent that don't describe the vault after their write. */
    manifestErrors: [] as string[],
    /** Every manifest stored, per vault, oldest first (the manifest log). */
    logs: {} as Record<string, LogEntry[]>,
    /** Entries one manifest-log answer holds at most. */
    logPage: 2000,

    /** The link of the vault's current manifest (null: it has none). */
    linkOf(vaultId: string): string | null {
      const v = s.vaults.find((x) => x.id === vaultId);
      return v?.manifest && v.manifest_prev && (v.manifest_seq ?? 0) > 0 ? manifestLink(v.manifest_seq ?? 0, v.manifest_prev, v.manifest) : null;
    },

    /** Store a manifest as the vault's current one, and list it in the vault's log. */
    setManifest(vaultId: string, m: { seq: number; prev: string; sealed: string }) {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      Object.assign(v, { manifest: m.sealed, manifest_seq: m.seq, manifest_prev: m.prev, manifest_ok: true });
      s.logs[vaultId] = [...(s.logs[vaultId] ?? []), { seq: m.seq, prev: m.prev, digest: dataHash(m.sealed) }];
    },

    clock(): number {
      return s.now ?? Math.floor(Date.now() / 1000);
    },

    /** The vault's rows as its manifest counts them. */
    manifestRows(vaultId: string) {
      return s.items.filter((i) => i.vault_id === vaultId).map((i) => ({ id: i.id, deleted_at: i.deleted_at, data: i.data }));
    },

    /**
     * Another device (with the vault's key) writes the vault's manifest for the items as they are now: always the
     * next version (the server takes no other), naming the manifest the server holds now as its predecessor (what a
     * write, a key replacement and a baseline, "Use the server's copy" by someone with write access, all do).
     */
    remanifest(vaultId: string) {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      const w = manifestKey(v.wrapped_key).manifestStart(v.id, v.key_epoch, (v.manifest_seq ?? 0) + 1, s.linkOf(vaultId), s.manifestRows(vaultId));
      s.setManifest(vaultId, w);
    },

    /** After a write elsewhere: the manifest follows, when the vault has one. */
    follow(vaultId: string) {
      if ((s.vaults.find((x) => x.id === vaultId)?.manifest_seq ?? 0) > 0) s.remanifest(vaultId);
    },

    /** Another device starts the vault's manifest (a vault write: its number goes up). */
    startManifestElsewhere(vaultId: string) {
      s.revision++;
      s.bump(vaultId);
      s.remanifest(vaultId);
    },

    /** The manifest a write must carry for `vaultId`: an error reply, or null when it is in order (`sent`: what came). */
    manifestFor(vaultId: string, sent: SentManifest[] | SentManifest | undefined): Reply | null {
      const v = s.vaults.find((x) => x.id === vaultId);
      const list = Array.isArray(sent) ? sent : sent ? [sent] : [];
      const mine = list.find((m) => m.vault_id === vaultId);
      const seq = v?.manifest_seq ?? 0;
      if (seq === 0) return mine ? { status: 409, body: { error: "manifest_conflict", message: "this vault has no manifest" } } : null;
      if (!mine) return { status: 400, body: { error: "manifest_required", message: "Update PassAuth to change this vault." } };
      if (typeof mine.prev !== "string" || !LINK.test(mine.prev)) return { status: 400, body: { error: "bad_request", message: "prev is not a link" } };
      if (mine.seq !== seq + 1 || mine.prev !== s.linkOf(vaultId)) return { status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } };
      return null;
    },

    /** Store the manifest a write carried (after the write was applied) and check that it describes the vault now. */
    storeManifest(vaultId: string, sent: SentManifest[] | SentManifest | undefined): Reply | null {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      const list = Array.isArray(sent) ? sent : sent ? [sent] : [];
      const mine = list.find((m) => m.vault_id === vaultId);
      if (!mine) return null;
      s.setManifest(vaultId, { seq: mine.seq, prev: String(mine.prev), sealed: mine.sealed });
      let status = "error";
      try {
        status = manifestKey(v.wrapped_key).manifestVerify(v.id, v.key_epoch, mine.seq, String(mine.prev), mine.sealed, null, null, null, s.manifestRows(vaultId)).status;
      } catch (e) {
        status = `error: ${e instanceof Error ? e.message : String(e)}`;
      }
      if (status === "ok") return null;
      s.manifestErrors.push(`${vaultId} v${mine.seq}: ${status}`);
      return { status: 500, body: { error: "internal", message: "the manifest doesn't describe the vault" } };
    },

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
      s.follow(vaultId);
    },

    /** Another device edits an item (same key). */
    editElsewhere(id: string, patch: Record<string, unknown>) {
      const i = s.items.find((x) => x.id === id)!;
      i.data = JSON.stringify({ ...JSON.parse(i.data), ...patch });
      i.revision = ++s.revision;
      i.seq = s.bump(i.vault_id);
      s.follow(i.vault_id);
    },

    /** Another device moves an item to the trash (`at`: when, Unix seconds). */
    trashElsewhere(id: string, at?: number) {
      const i = s.items.find((x) => x.id === id)!;
      i.deleted_at = at ?? s.clock();
      i.revision = ++s.revision;
      i.seq = s.bump(i.vault_id);
      s.follow(i.vault_id);
    },

    /** Another device adds an item (encrypted under the vault's current key, like the fake core does). */
    addElsewhere(id: string, vaultId: string, data: string) {
      const v = s.vaults.find((x) => x.id === vaultId)!;
      s.items.push({ id, vault_id: vaultId, item_key: `${v.wrapped_key}:${id}`, data, revision: ++s.revision, deleted_at: null, seq: s.bump(vaultId) });
      s.follow(vaultId);
    },

    /** Another device deletes an item for good. */
    deleteElsewhere(id: string) {
      const i = s.items.find((x) => x.id === id)!;
      s.items = s.items.filter((x) => x !== i);
      s.revision++;
      s.tombstones.push({ id, vault_id: i.vault_id, seq: s.bump(i.vault_id) });
      s.follow(i.vault_id);
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
      const manifestSeq = (vaultId: string) => (v2("vault_manifest") ? { manifest_seq: s.vaults.find((v) => v.id === vaultId)?.manifest_seq ?? 0, manifest_link: s.linkOf(vaultId) } : {});
      if (req.method === "GET" && req.path === "/config") {
        if (s.outdated === "old") return { body: { name: "PassAuth", version: "0.3.0" } };
        const features = s.outdated === "unsigned" ? s.features.filter((f) => f !== "signed_sharing") : [...new Set([...s.features, "signed_sharing"])];
        return { body: { name: "PassAuth", version: "0.15.0", api: 2, features, limits: s.limits } };
      }
      const startOf = /^\/vaults\/([^/]+)\/manifest$/.exec(req.path);
      if (req.method === "PUT" && startOf) {
        const v = s.vaults.find((x) => x.id === startOf[1]);
        const b = req.body;
        if (!v) return { status: 404, body: { error: "not_found", message: "not found" } };
        if (v.role === "read") return { status: 403, body: { error: "forbidden", message: "read only" } };
        if (typeof b.prev !== "string" || !LINK.test(b.prev)) return { status: 400, body: { error: "bad_request", message: "prev is not a link" } };
        // Every manifest is exactly one version above the one it replaces (a first one: 0 → 1).
        if (b.seq !== b.base_seq + 1) return { status: 400, body: { error: "bad_request", message: "seq must be base_seq + 1" } };
        if ((v.manifest_seq ?? 0) !== b.base_seq || (v.seq ?? 0) !== b.vault_seq || b.prev !== (s.linkOf(v.id) ?? ZERO_LINK)) {
          return { status: 409, body: { error: "manifest_conflict", message: "the vault changed; sync and try again" } };
        }
        if (b.base_seq === 0 && !v.manifest_ok) return { status: 409, body: { error: "manifest_not_ready", message: "some apps are too old" } };
        s.revision++;
        const seq = s.bump(v.id);
        const bad = s.storeManifest(v.id, { vault_id: v.id, seq: b.seq, prev: b.prev, sealed: b.sealed });
        if (bad) return bad;
        return { body: { revision: s.revision, vault_seq: seq, ...manifestSeq(v.id) } };
      }
      const purgeOf = /^\/vaults\/([^/]+)\/trash\/purge$/.exec(req.path);
      if (req.method === "POST" && purgeOf) {
        const v = s.vaults.find((x) => x.id === purgeOf[1]);
        const b = req.body;
        if (!v) return { status: 404, body: { error: "not_found", message: "not found" } };
        const targets = (b.items as { id: string; revision?: number }[]).map((t) => ({ t, i: s.items.find((x) => x.id === t.id && x.vault_id === v.id && x.deleted_at) }));
        if (targets.some(({ t, i }) => !i || (t.revision !== undefined && t.revision !== i.revision))) {
          return { status: 409, body: { error: "revision_conflict", message: "item changed on another device; sync and retry" } };
        }
        const refused = s.manifestFor(v.id, b.manifests);
        if (refused) return refused;
        s.revision++;
        const seq = s.bump(v.id);
        for (const { i } of targets) {
          s.items = s.items.filter((x) => x !== i);
          s.tombstones.push({ id: i!.id, vault_id: v.id, seq });
        }
        const bad = s.storeManifest(v.id, b.manifests);
        if (bad) return bad;
        return { body: { purged: targets.length, revision: s.revision, vault_seq: seq, ...manifestSeq(v.id) } };
      }
      const logOf = /^\/vaults\/([^/]+)\/manifest-log$/.exec(req.path);
      if (req.method === "GET" && logOf) {
        const after = Number(req.query.after ?? 0);
        if (!s.vaults.some((x) => x.id === logOf[1])) return { status: 404, body: { error: "not_found", message: "not found" } };
        if (!Number.isSafeInteger(after) || after < 0) return { status: 400, body: { error: "bad_request", message: "bad range" } };
        const rest = (s.logs[logOf[1]!] ?? []).filter((e) => e.seq > after).sort((a, b) => a.seq - b.seq);
        return { body: { entries: rest.slice(0, s.logPage), more: rest.length > s.logPage } };
      }
      if (req.method === "GET" && req.path === "/sync") return { body: s.syncAnswer(req.query) };
      if (req.method === "GET" && req.path === "/sync/revision") {
        return { body: { revision: s.revision, ...(v2("delta_sync") ? { vaults: Object.fromEntries(s.vaults.map((v) => [v.id, v.seq ?? 0])) } : {}) } };
      }
      if (req.method === "DELETE" && req.path.startsWith("/items/")) {
        const i = s.items.find((x) => x.id === req.path.slice("/items/".length));
        if (!i) return { status: 404, body: { error: "not_found", message: "not found" } };
        if (req.query.revision !== undefined && Number(req.query.revision) !== i.revision) {
          return { status: 409, body: { error: "revision_conflict", message: "item changed on another device; sync and retry" } };
        }
        const sent = req.query.manifest_seq !== undefined ? { vault_id: i.vault_id, seq: Number(req.query.manifest_seq), prev: req.query.manifest_prev, sealed: req.query.manifest ?? "" } : undefined;
        const refused = s.manifestFor(i.vault_id, sent);
        if (refused) return refused;
        i.deleted_at = s.clock();
        i.revision = ++s.revision;
        i.seq = s.bump(i.vault_id);
        const bad = s.storeManifest(i.vault_id, sent);
        if (bad) return bad;
        return { body: { revision: i.revision, ...(v2("delta_sync") ? { vault_seq: i.seq } : {}), ...manifestSeq(i.vault_id) } };
      }
      if (req.method === "POST" && req.path === "/items") {
        const b = req.body;
        if (epochChanged(b.vault_id, b.key_epoch)) return keyChanged;
        const existing = s.items.find((i) => i.id === b.id);
        if (existing) {
          if (v2("idempotent_create") && existing.vault_id === b.vault_id && existing.item_key === b.key && existing.data === b.data) {
            // A repeat: nothing is written, the manifest sent is ignored, and the answer names the vault as it is.
            return { body: { id: b.id, revision: existing.revision, ...(v2("delta_sync") ? { vault_seq: s.vaults.find((v) => v.id === b.vault_id)?.seq } : {}), ...manifestSeq(b.vault_id) } };
          }
          return v2("error_codes")
            ? { status: 409, body: { error: "item_exists", message: "item id already exists" } }
            : { status: 409, body: { error: "conflict", message: "item id already exists" } };
        }
        const refused = s.manifestFor(b.vault_id, b.manifests);
        if (refused) return refused;
        s.items.push({ id: b.id, vault_id: b.vault_id, item_key: b.key, data: b.data, revision: ++s.revision, deleted_at: null, seq: s.bump(b.vault_id) });
        const bad = s.storeManifest(b.vault_id, b.manifests);
        if (bad) return bad;
        return { body: { id: b.id, revision: s.revision, ...(v2("delta_sync") ? { vault_seq: s.vaults.find((v) => v.id === b.vault_id)?.seq } : {}), ...manifestSeq(b.vault_id) } };
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
        const refused = s.manifestFor(b.vault_id, b.manifests);
        if (refused) return refused;
        Object.assign(i, { vault_id: b.vault_id, item_key: b.key, data: b.data, revision: ++s.revision, seq: s.bump(b.vault_id) });
        const bad = s.storeManifest(b.vault_id, b.manifests);
        if (bad) return bad;
        return { body: { id: i.id, revision: s.revision, ...(v2("delta_sync") ? { vault_seq: i.seq } : {}), ...manifestSeq(b.vault_id) } };
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
    if (!(summary && i.deleted_at)) return rest;
    return { ...rest, item_key: undefined, data: undefined, ...(manifests && !s.omitHashes ? { data_sha256: dataHash(i.data) } : {}) };
  };
  const manifests = s.features.includes("vault_manifest");
  const vaults = s.vaults.map((v) => {
    const { seq, manifest, manifest_seq, manifest_prev, manifest_ok, ...rest } = v;
    return {
      ...rest,
      ...(s.features.includes("key_epoch") ? {} : { key_epoch: undefined }),
      ...(delta ? { seq: seq ?? 0 } : {}),
      ...(manifests
        ? {
            manifest: manifest ?? null,
            manifest_seq: manifest_seq ?? 0,
            manifest_prev: (manifest_seq ?? 0) > 0 ? (manifest_prev ?? null) : null,
            manifest_ok: (manifest_seq ?? 0) > 0 || manifest_ok === true,
          }
        : {}),
    };
  });
  const base = { revision: s.revision, user: s.user, bundle: s.bundle, vaults, invitations: s.invitations, ...(manifests ? { server_time: s.clock(), trash_days: s.trashDays } : {}) };
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
