/**
 * Delta sync and live sync in the service worker: the pure parts (unit-tested in sync-rules.test.ts). How answers are
 * merged is the web vault's (`@web/lib/delta`: `mergeSync`, `applyOwnWrite`, `afterWrite`, `noticeAction`), used as
 * it is. This file adds what only the extension needs:
 * - the offline copy's shape in IndexedDB: the merged snapshot in the shape of a full `/sync` answer, so its cursor,
 *   its vault numbers and its rows are always written (and read) together in one record, and older versions of the
 *   extension still read it as an ordinary answer;
 * - whether a `GET /sync/revision` answer says the copy lacks something (`isStale`);
 * - reading live-sync messages (`readLiveMessage`), why the server closed the socket (`closedFor`) and the reconnect
 *   delay (`backoffMs`).
 */
import type { Snapshot, SyncNotice } from "@web/lib/delta";
import { readInvitations } from "@web/lib/invitations";
import { isSyncResponse, isSyncVaultRow, type SyncInvitation, type SyncItemRow, type SyncResponse } from "@web/lib/types";
import type { SignedInvitation, StoredVerdict } from "./signed-sharing";

/**
 * The offline copy as IndexedDB keeps it: a full `/sync` answer (never `delta: true`) plus `own`, the vault numbers
 * after this browser's own writes that were shown without asking the server (`applyOwnWrite`). The cursor stays
 * behind those writes, so the next delta sends their rows again.
 */
export interface StoredSync extends SyncResponse {
  own?: Record<string, number>;
  /**
   * Signed sharing: each vault's last verdict with the row it was made for (signed-sharing.ts `stampOf`), so an
   * offline unlock or a service-worker restart never uses a vault that failed, and checks only rows it has no verdict for.
   */
  trust?: Record<string, StoredVerdict>;
  /**
   * Written with the signed-sharing checks off (round 5 H): such a copy is never a source of grandfathering candidates.
   * Only a copy with neither this nor `trust` (written before signed sharing existed) counts all its rows as usable.
   */
  checks?: "off";
}

/** Signed-sharing fields of an invitation that `readInvitations` (web) doesn't keep: the extension checks them. */
const SIGNED_FIELDS = ["key_epoch", "share", "member_roster", "member_roster_seq"] as const;

/**
 * `list` (read by `readInvitations`) with each invitation's signed-sharing fields from `raw` (the answer's own list)
 * put back, matched by vault id: servers with `signed_sharing` send `key_epoch`, `share`, `member_roster` and
 * `member_roster_seq`, and the signer's keys inside `share`.
 */
export function withSignedFields(list: SyncInvitation[], raw: unknown): SignedInvitation[] {
  if (!Array.isArray(raw)) return list;
  const byId = new Map<string, Record<string, unknown>>();
  for (const r of raw) {
    const v = r as Record<string, unknown> | null;
    if (v && typeof v === "object" && typeof v.vault_id === "string" && !byId.has(v.vault_id)) byId.set(v.vault_id, v);
  }
  return list.map((inv) => {
    const r = byId.get(inv.vault_id);
    if (!r) return inv;
    const extra: Record<string, unknown> = {};
    for (const f of SIGNED_FIELDS) if (f in r) extra[f] = r[f];
    return { ...inv, ...extra };
  });
}

const isRow = (r: unknown): r is SyncItemRow => !!r && typeof r === "object" && typeof (r as SyncItemRow).id === "string" && typeof (r as SyncItemRow).vault_id === "string";

/** A snapshot as one IndexedDB record. */
export function toStored(s: Snapshot): StoredSync {
  const own = Object.keys(s.own).length ? { own: { ...s.own } } : {};
  return {
    revision: s.revision,
    ...(s.cursor ? { cursor: s.cursor } : {}),
    user: s.user,
    bundle: s.bundle,
    vaults: s.vaults,
    items: [...s.items.values()],
    invitations: s.invitations,
    ...own,
  };
}

/**
 * The snapshot an offline copy holds (a copy from before delta sync has no cursor: the next sync fetches everything),
 * checked like a server's answer before anything in it reaches the core: null when the copy isn't one (then a full
 * sync), and vault rows whose key fields aren't text (`isSyncVaultRow`) are left out, like rows of a `/sync` answer.
 */
export function fromStored(v: StoredSync): Snapshot | null {
  if (!isSyncResponse(v)) return null;
  const own: Record<string, number> = {};
  if (v.own && typeof v.own === "object") for (const [id, seq] of Object.entries(v.own)) if (typeof seq === "number" && Number.isSafeInteger(seq)) own[id] = seq;
  return {
    revision: v.revision,
    cursor: typeof v.cursor === "string" && v.cursor ? v.cursor : null,
    user: v.user,
    bundle: v.bundle,
    vaults: v.vaults.filter(isSyncVaultRow),
    items: new Map(v.items.filter(isRow).map((r) => [r.id, r])),
    invitations: withSignedFields(readInvitations(v.invitations), v.invitations),
    own,
  };
}

/** `GET /sync/revision`: the account's revision and (servers with delta sync) every vault's number. */
export interface RevisionAnswer {
  revision: number;
  vaults?: Record<string, number>;
}

/** A `/sync/revision` answer, or null when it isn't one. Vault numbers that aren't numbers make the whole list unknown. */
export function readRevision(v: unknown): RevisionAnswer | null {
  const r = v as { revision?: unknown; vaults?: unknown } | null;
  if (!r || typeof r !== "object" || typeof r.revision !== "number") return null;
  const vaults = r.vaults;
  if (!vaults || typeof vaults !== "object" || Array.isArray(vaults)) return { revision: r.revision };
  const out: Record<string, number> = {};
  for (const [id, seq] of Object.entries(vaults)) {
    if (typeof seq !== "number") return { revision: r.revision };
    out[id] = seq;
  }
  return { revision: r.revision, vaults: out };
}

/** The copy's number for each vault it reads (own writes shown included), or null when it has no vault numbers. */
function knownNumbers(s: Snapshot): Map<string, number> | null {
  const out = new Map<string, number>();
  for (const v of s.vaults) {
    if (typeof v.seq !== "number") return null;
    out.set(v.id, Math.max(v.seq, s.own[v.id] ?? v.seq));
  }
  return out;
}

/**
 * `GET /sync/revision` answered `r`: does the copy `s` lack something (null: there is no copy)? Without vault numbers
 * (an older server, or a copy from before delta sync) only a newer revision counts, as before. With them: any other
 * revision (profile, bundle and membership changes carry no vault number; after this browser's own writes were shown
 * without asking, the copy's revision is behind, which costs one small delta), a vault whose number differs, a vault
 * the copy doesn't have, or one it has that is gone.
 */
export function isStale(r: RevisionAnswer, s: Snapshot | null): boolean {
  if (!s) return true;
  const mine = s.cursor ? knownNumbers(s) : null;
  if (!r.vaults || !mine) return r.revision > s.revision;
  if (r.revision !== s.revision) return true;
  const theirs = Object.entries(r.vaults);
  if (theirs.length !== mine.size) return true;
  return theirs.some(([id, seq]) => mine.get(id) !== seq);
}

/**
 * A message from the live-sync socket (`/api/ws`, the server's ws.rs). `auth_request*`: sign-in approvals
 * (sign-in-requests.ts). `two_step_required`: the server now requires two-step login of this account (its admin turned
 * the policy on); the socket closes right after it.
 */
export type LiveMessage = { type: "hello"; origin: string } | SyncNotice | { type: "logout" } | { type: "two_step_required" } | { type: "auth_request" | "auth_request_answered"; id: string };

/** One text frame from the socket, or null for anything else (unknown types are ignored). */
export function readLiveMessage(text: unknown): LiveMessage | null {
  if (typeof text !== "string" || text.length > 64 * 1024) return null;
  let msg: unknown;
  try {
    msg = JSON.parse(text);
  } catch {
    return null;
  }
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) return null;
  const m = msg as Record<string, unknown>;
  if (m.type === "hello") return typeof m.origin === "string" ? { type: "hello", origin: m.origin } : null;
  if (m.type === "logout") return { type: "logout" };
  if (m.type === "two_step_required") return { type: "two_step_required" };
  if (m.type === "auth_request" || m.type === "auth_request_answered") return typeof m.id === "string" && m.id && m.id.length <= 128 ? { type: m.type, id: m.id } : null;
  if (m.type !== "sync") return null;
  const notice: SyncNotice = { type: "sync" };
  if (typeof m.revision === "number") notice.revision = m.revision;
  if (m.vaults && typeof m.vaults === "object" && !Array.isArray(m.vaults)) notice.vaults = m.vaults as Record<string, unknown>;
  if (typeof m.origin === "string") notice.origin = m.origin;
  return notice;
}

/**
 * Why the server closed the socket, when it means "don't come back": 1008 (policy violation) `two_step_required` — the
 * account must set up two-step login first, so reconnecting would only be refused again. Null for any other close.
 */
export function closedFor(code: unknown, reason: unknown): "two_step" | null {
  return code === 1008 && reason === "two_step_required" ? "two_step" : null;
}

/** Reconnect delay before attempt `attempt` (0 = the first): 1 s, 2 s, 4 s … at most 60 s, each ±20% (`random` in [0, 1)). */
export function backoffMs(attempt: number, random: number): number {
  const base = Math.min(60_000, 1000 * 2 ** Math.min(Math.max(0, Math.floor(attempt)), 6));
  const r = Math.min(Math.max(random, 0), 1);
  return Math.round(Math.min(60_000, base * (0.8 + 0.4 * r)));
}

/** `wss://server/api/ws?access_token=…` (browser sockets can't send headers; only this route takes a token in the URL). */
export function socketUrl(server: string, accessToken: string): string {
  const base = server.replace(/^https:\/\//i, "wss://").replace(/^http:\/\//i, "ws://");
  return `${base}/api/ws?access_token=${encodeURIComponent(accessToken)}`;
}
