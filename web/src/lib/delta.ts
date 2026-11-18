/**
 * Delta sync: how the web vault and the desktop app merge `/sync` answers and decide when to ask the server at all.
 * Pure (no WASM, no network, no React) and unit-tested in `delta.test.ts`; `vault.ts` holds the state.
 *
 * Servers with the `delta_sync` feature send an opaque `cursor` and each vault's `seq` (it goes up with every write
 * into the vault). `GET /sync?since=<cursor>` then answers only what changed (`delta: true`): every vault header,
 * the items written after the cursor plus every item of the `reset` vaults, and `deleted` (items deleted for good or
 * moved out of a vault). The client keeps the encrypted rows of its answers together with the cursor they came with
 * (a `Snapshot`, in memory only, like everything else the web vault and the desktop app hold), so a cursor is never
 * kept without the items it describes.
 */
import { readInvitations } from "./invitations";
import { isBundle, isSyncUser, isSyncVaultRow, type Bundle, type SyncInvitation, type SyncItemRow, type SyncResponse, type SyncVaultRow } from "./types";

export interface Snapshot {
  /** The account's sync revision in the last answer merged in. */
  revision: number;
  /** Cursor of the last answer merged in; null when the server sent none. */
  cursor: string | null;
  user: SyncResponse["user"];
  bundle: Bundle;
  /** Every vault the account reads, as the last answer listed them. */
  vaults: SyncVaultRow[];
  /** Encrypted item rows by id. */
  items: Map<string, SyncItemRow>;
  /** Vaults shared with the account and not accepted yet: every answer, full or delta, lists them all (none from older servers). */
  invitations: SyncInvitation[];
  /**
   * This client's own writes shown without asking the server (`applyOwnWrite`), as each vault's number after them.
   * The cursor stays behind them, so the next delta sends those rows again and they are merged over what was shown.
   */
  own: Readonly<Record<string, number>>;
  /** Vault manifests: the server's clock and trash retention of the last answer merged in (servers with `vault_manifest`). */
  serverTime?: number;
  trashDays?: number;
}

export interface Merged {
  snapshot: Snapshot;
  /**
   * The answer is older than one of this client's own writes it showed already (a vault's number in the answer is
   * below it): the write may be missing again, so sync once more. Not expected; a safety net.
   */
  behind: boolean;
}

/** A delta answer the client can't use (malformed): fetch everything instead. */
export class DeltaError extends Error {}

const isString = (v: unknown): v is string => typeof v === "string";
const wholeNumber = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
/** A number the app counts with or compares, when the server sent it: a whole number from 0 to 2^53 − 1. */
const optWhole = (v: unknown) => v === undefined || wholeNumber(v);

/**
 * Every field of the answer that the app keeps or hands to the core has its type (the core's string parameters must
 * never get anything else): the user, the bundle, each vault row (`wrapped_key`, `key_kind`, `meta`, `role` as strings,
 * the numbers as numbers), each item's ids, and a delta's `deleted` and `reset`. The numbers the apps count with or
 * compare (a vault's `seq`, `manifest_seq` and `key_epoch`, an item's `deleted_at`) are whole numbers from 0 to
 * 2^53 − 1 or the answer is refused as a whole: no arithmetic ever runs on anything else. (`deleted_at` 0 passes here
 * and is refused by the core as "no time", which makes its vault a mismatch.)
 */
function check(resp: SyncResponse) {
  if (!isSyncUser(resp.user)) throw new DeltaError("user");
  if (!isBundle(resp.bundle)) throw new DeltaError("bundle");
  if (resp.cursor !== undefined && !isString(resp.cursor)) throw new DeltaError("cursor");
  for (const v of resp.vaults) if (!isSyncVaultRow(v) || !optWhole(v.seq) || !optWhole(v.manifest_seq) || !optWhole(v.key_epoch)) throw new DeltaError("vault");
  for (const row of resp.items) {
    if (!isString(row?.id) || !isString(row.vault_id)) throw new DeltaError("item");
    const at: unknown = row.deleted_at;
    if (at !== null && at !== undefined && !wholeNumber(at)) throw new DeltaError("item");
  }
  if (resp.delta !== true) return;
  if (resp.deleted !== undefined && (!Array.isArray(resp.deleted) || !resp.deleted.every((d) => isString(d?.id) && isString(d.vault_id))))
    throw new DeltaError("deleted");
  if (resp.reset !== undefined && (!Array.isArray(resp.reset) || !resp.reset.every(isString))) throw new DeltaError("reset");
}

/**
 * Merge a `/sync` answer into `prev`. An answer without `delta: true` replaces everything. A delta needs `prev` of
 * the same account and returns null otherwise (fetch everything instead): `deleted` first (an entry removes the item
 * only from the vault it names, so a later move back is kept), then all items of the `reset` vaults go, then `items`
 * are upserted by id (an item moved between two readable vaults is in both lists), and finally every item of a vault
 * missing from `vaults` goes (the account lost it). Throws `DeltaError` for a malformed answer (`check`).
 */
export function mergeSync(prev: Snapshot | null, resp: SyncResponse): Merged | null {
  check(resp);
  const delta = resp.delta === true;
  if (delta && (!prev || prev.user.id !== resp.user.id)) return null;
  let items: Map<string, SyncItemRow>;
  if (delta && prev) {
    items = new Map(prev.items);
    for (const d of resp.deleted ?? []) if (items.get(d.id)?.vault_id === d.vault_id) items.delete(d.id);
    const reset = new Set(resp.reset ?? []);
    if (reset.size) for (const [id, row] of items) if (reset.has(row.vault_id)) items.delete(id);
    for (const row of resp.items) items.set(row.id, row);
    const live = new Set(resp.vaults.map((v) => v.id));
    for (const [id, row] of items) if (!live.has(row.vault_id)) items.delete(id);
  } else {
    items = new Map(resp.items.map((row) => [row.id, row]));
  }
  const seqs = new Map(resp.vaults.map((v) => [v.id, v.seq]));
  const behind =
    !!prev &&
    Object.entries(prev.own).some(([id, own]) => {
      const now = seqs.get(id);
      return typeof now === "number" && now < own;
    });
  return {
    snapshot: {
      revision: resp.revision,
      cursor: isString(resp.cursor) ? resp.cursor : null,
      user: resp.user,
      bundle: resp.bundle,
      vaults: resp.vaults,
      items,
      // Not a change since the cursor: the whole list, every time (an accepted vault then arrives whole, as `reset`).
      invitations: readInvitations(resp.invitations),
      own: {},
      ...(wholeNumber(resp.server_time) ? { serverTime: resp.server_time } : {}),
      ...(wholeNumber(resp.trash_days) ? { trashDays: resp.trash_days } : {}),
    },
    behind,
  };
}

/** The vault's number this client has (its own writes shown included); undefined without delta sync or for a vault it doesn't read. */
export function knownSeq(s: Snapshot | null, vaultId: string): number | undefined {
  const v = s?.vaults.find((x) => x.id === vaultId);
  if (!s || typeof v?.seq !== "number") return undefined;
  return Math.max(v.seq, s.own[vaultId] ?? v.seq);
}

/**
 * The vault manifest a write carried (`manifest.ts`): the vault's manifest version after the write, its sealed text
 * and the link of the manifest it replaced (`prev`; the vault row keeps the three together).
 */
export interface SentManifest {
  seq: number;
  sealed: string;
  prev?: string;
}

/**
 * One of this client's own item writes, as the server stored it. `manifest`: the vault manifest the write carried and
 * the server stored with it (its answer's `manifest_seq` is that version); the vault row then holds it too.
 */
export type OwnWrite =
  | { kind: "upsert"; row: SyncItemRow; vaultSeq: number; manifest?: SentManifest }
  | { kind: "remove"; id: string; vaultId: string; vaultSeq: number; manifest?: SentManifest };

/** Show an own write without asking the server; only after `afterWrite` said "apply". */
export function applyOwnWrite(s: Snapshot, w: OwnWrite): Snapshot {
  const items = new Map(s.items);
  const vaultId = w.kind === "upsert" ? w.row.vault_id : w.vaultId;
  if (w.kind === "upsert") items.set(w.row.id, w.row);
  else if (items.get(w.id)?.vault_id === w.vaultId) items.delete(w.id);
  const next = { ...s, items, own: { ...s.own, [vaultId]: w.vaultSeq } };
  return w.manifest ? applyOwnManifest(next, vaultId, w.manifest, w.vaultSeq) : next;
}

/**
 * The vault row holds a manifest this client stored itself (with an own write shown without asking, a first manifest
 * or a new baseline) and the vault's number after that request. The items are untouched.
 */
export function applyOwnManifest(s: Snapshot, vaultId: string, manifest: SentManifest, vaultSeq: number): Snapshot {
  return {
    ...s,
    vaults: s.vaults.map((v) =>
      v.id === vaultId ? { ...v, manifest: manifest.sealed, manifest_seq: manifest.seq, ...(manifest.prev !== undefined ? { manifest_prev: manifest.prev } : {}) } : v,
    ),
    own: { ...s.own, [vaultId]: vaultSeq },
  };
}

/**
 * What to do after an own write that answered `vaultSeq` (the vault's number after it):
 * - "none": the client already has that number, so a sync since then brought the write;
 * - "apply": it is exactly the next number, so nothing else happened in the vault and the write can be shown as sent
 *   (`canApply`: the client knows the stored row, i.e. a create, an edit in place, a restore or a delete for good);
 * - "sync": anything else (other writes in between, numbers out of order, a move, a server without numbers).
 *
 * Vault manifests (`manifest`, optional): `sent` is the manifest version the write carried (undefined: none) and
 * `answered` the answer's `manifest_seq`. A write is shown as sent only when the two agree: a write that carried one
 * must be answered with exactly that version, and one that carried none must not be answered with a version above 0.
 */
export function afterWrite(
  known: number | undefined,
  vaultSeq: unknown,
  canApply: boolean,
  manifest?: { sent: number | undefined; answered: unknown },
): "none" | "apply" | "sync" {
  if (known === undefined || typeof vaultSeq !== "number") return "sync";
  if (vaultSeq <= known) return "none";
  if (manifest && (manifest.sent === undefined ? typeof manifest.answered === "number" && manifest.answered > 0 : manifest.answered !== manifest.sent)) return "sync";
  return vaultSeq === known + 1 && canApply ? "apply" : "sync";
}

/** A `{"type":"sync"}` live-sync message. */
export interface SyncNotice {
  type: "sync";
  /** The account's new sync revision. */
  revision?: number;
  /** New numbers of the vaults written; `{}` for profile or account changes (or after the socket missed messages). */
  vaults?: Record<string, unknown>;
  /** The session that wrote, if one session made every change in the message. */
  origin?: string;
}

/**
 * Whether a live-sync message needs a sync. Without delta sync: when its revision is newer (as before). With it:
 * - not when its revision is at most `revision`, the account revision of the last answer merged in: that answer was
 *   read after the change (one snapshot), whatever the vault numbers say (e.g. a vault deleted since is unknown here);
 * - when a vault in it has a newer number than this client's, or is one it doesn't know (shared with the account);
 * - for `vaults: {}` (profile or account changes, or a socket that missed messages): when it is newer.
 * Own writes shown without asking don't move `revision`, so their messages are judged by the vault numbers alone.
 * `origin` is deliberately not consulted: every tab and window sharing a session shares its origin, so a write by
 * "this session" may still be missing here.
 */
export function noticeAction(
  msg: SyncNotice,
  known: (vaultId: string) => number | undefined,
  revision: number,
  delta: boolean,
): "sync" | "skip" {
  const hasRevision = typeof msg.revision === "number";
  const newer = hasRevision && (msg.revision as number) > revision;
  const vaults = msg.vaults;
  if (!delta || !vaults || typeof vaults !== "object" || Array.isArray(vaults)) return newer ? "sync" : "skip";
  if (hasRevision && !newer) return "skip";
  const entries = Object.entries(vaults);
  if (entries.length === 0) return "sync";
  return entries.some(([id, seq]) => {
    const have = known(id);
    return have === undefined || typeof seq !== "number" || seq > have;
  })
    ? "sync"
    : "skip";
}

/** The fields of a vault row that decide its key: when one changes, the key handle must be opened again. */
export function vaultKeyChanged(a: SyncVaultRow, b: SyncVaultRow): boolean {
  return a.wrapped_key !== b.wrapped_key || a.key_kind !== b.key_kind || a.key_epoch !== b.key_epoch;
}

/** The same encrypted item in the same vault (revision and trash state may differ): its decrypted copy still holds. */
export function sameCiphertext(a: SyncItemRow, b: SyncItemRow): boolean {
  return a === b || (a.vault_id === b.vault_id && a.item_key === b.item_key && a.data === b.data);
}
