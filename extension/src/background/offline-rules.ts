/**
 * Offline changes (waiting to sync), the pure part: ARCHITECTURE "Offline changes". The list's shape, how a new
 * change is merged into the one an item already has, how the list is shown over the offline copy, what the sender
 * does with each change (send, done, hold, conflict), what an error means, and the user's choices in a conflict.
 * Nothing here touches storage, the network or keys: background/vault.ts does (section "offline changes").
 */
import type { Item } from "@web/lib/types";
import { DISCARD_TEXT, lostText } from "../shared/offline-text";

export { DISCARD_TEXT, lostText };

/** The list's own format version (`{"version": 1, "changes": [...]}`). */
export const OFFLINE_LIST_VERSION = 1;
/** At most this many changes wait; the next one is refused with `TOO_MANY_TEXT`. */
export const MAX_OFFLINE_CHANGES = 500;
/** How often one change is synced and decided again after `revision_conflict`, or sent again after a manifest/key refusal. */
export const SEND_TRIES = 3;

export const TOO_MANY_TEXT = "Too many changes are waiting. Connect to the internet before making more.";
export const TRASHED_OFFLINE_TEXT = "This item is waiting to move to the trash. Restoring it needs a connection.";
export const WAITING_MARK = "Waiting to sync";
export const CONFLICT_MARK = "Changed on another device";
export const CHANGED_REASON = "This item was changed on another device.";
export const DELETED_REASON = "This item was deleted on another device.";
export const VAULT_GONE_REASON = "The vault is gone, or it was no longer shared with you.";
export const READ_ONLY_REASON = "You can no longer change items in this vault.";
export const SHARING_HELD_REASON = "This vault didn't pass PassAuth's sharing checks, or it waits for you to accept it.";
export const BUSY_REASON = "The vault kept changing while PassAuth sent this. It's sent again at the next sync.";
export const OFFLINE_COPY_SUFFIX = " (offline copy)";
/** The list doesn't decrypt for this account: it is dropped, with this notice. */
export const DROPPED_TEXT = "Changes waiting on this device couldn't be read and were removed.";
/** The list can't be read for another reason: it is kept, and nothing is written over it. */
export const OFFLINE_UNREADABLE_TEXT = "Changes waiting on this device can't be read.";

export type ChangeKind = "create" | "edit" | "trash";
export type ChangeState = "waiting" | "held" | "conflict";

/** The exact body of the last attempt that may have reached the server. */
export interface SentBody {
  key: string;
  data: string;
  key_epoch: number | null;
}

export interface OfflineChange {
  id: string;
  kind: ChangeKind;
  vault_id: string;
  item_id: string;
  /** The server revision the change started from; null for a create (and a create turned into a trash). */
  base_revision: number | null;
  /** The decrypted item as the editor saved it (create/edit); null for trash. */
  item: Item | null;
  sent: SentBody | null;
  /** ms */
  created_at: number;
  state: ChangeState;
  /** Shown for held/conflict, else null. */
  reason: string | null;
}

export interface OfflineList {
  version: number;
  changes: OfflineChange[];
}

const KINDS: readonly string[] = ["create", "edit", "trash"];
const STATES: readonly string[] = ["waiting", "held", "conflict"];
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isRevision = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

function readSent(v: unknown): SentBody | null | undefined {
  if (v === null || v === undefined) return null;
  if (!isObj(v) || typeof v.key !== "string" || typeof v.data !== "string") return undefined;
  const epoch = v.key_epoch;
  if (epoch !== null && epoch !== undefined && !isRevision(epoch)) return undefined;
  return { key: v.key, data: v.data, key_epoch: epoch ?? null };
}

/** One change as stored, or null when it isn't one (dropped: a list from a newer version keeps what this one reads). */
export function readChange(v: unknown): OfflineChange | null {
  if (!isObj(v)) return null;
  const { id, kind, vault_id, item_id, base_revision, item, created_at, state, reason } = v;
  if (typeof id !== "string" || typeof kind !== "string" || !KINDS.includes(kind) || typeof vault_id !== "string" || typeof item_id !== "string") return null;
  if (!vault_id || !item_id) return null;
  if (base_revision !== null && !isRevision(base_revision)) return null;
  if (kind === "trash" ? item !== null : !isObj(item)) return null;
  const sent = readSent(v.sent);
  if (sent === undefined) return null;
  if (typeof created_at !== "number" || !Number.isFinite(created_at)) return null;
  if (typeof state !== "string" || !STATES.includes(state)) return null;
  if (reason !== null && typeof reason !== "string") return null;
  return { id, kind: kind as ChangeKind, vault_id, item_id, base_revision, item: (item as Item | null) ?? null, sent, created_at, state: state as ChangeState, reason };
}

/**
 * The opened list (JSON); null when it isn't a list this version reads (not JSON, no `changes`, another version): the
 * caller keeps it and writes nothing over it. Single changes it can't read, and changes for the same item after the
 * first, are dropped (one change per item).
 */
export function parseList(json: string): OfflineList | null {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isObj(raw) || raw.version !== OFFLINE_LIST_VERSION || !Array.isArray(raw.changes)) return null;
  const seen = new Set<string>();
  const changes: OfflineChange[] = [];
  for (const c of raw.changes) {
    const change = readChange(c);
    if (!change || seen.has(change.item_id)) continue;
    seen.add(change.item_id);
    changes.push(change);
  }
  return { version: OFFLINE_LIST_VERSION, changes: changes.slice(0, MAX_OFFLINE_CHANGES) };
}

export const serializeList = (list: OfflineList): string => JSON.stringify({ version: OFFLINE_LIST_VERSION, changes: list.changes });

/** A change the user just made, before it is merged. */
export interface NewChange {
  kind: ChangeKind;
  vault_id: string;
  item_id: string;
  base_revision: number | null;
  item: Item | null;
}

export class OfflineRuleError extends Error {
  constructor(
    readonly code: "too_many" | "trashed",
    message: string,
  ) {
    super(message);
    this.name = "OfflineRuleError";
  }
}

/**
 * The list with `incoming` merged in (one change per item): create + edit = create with the new item; edit + edit =
 * edit (first `base_revision`, newest item); edit + trash = trash (first `base_revision`); create + trash = removed,
 * unless `sent` is set (it may exist on the server): then a trash with `base_revision` null and `sent` kept. A change
 * waiting to move to the trash can't be edited. A merged change is decided again (state "waiting"). A new change past
 * `MAX_OFFLINE_CHANGES` is refused. `sent`: the body of an attempt that failed without an answer (a new change only).
 */
export function mergeChange(changes: readonly OfflineChange[], incoming: NewChange, now: number, newId: () => string, sent: SentBody | null = null): OfflineChange[] {
  const at = changes.findIndex((c) => c.item_id === incoming.item_id);
  if (at < 0) {
    if (incoming.kind === "trash" && incoming.item !== null) throw new Error("A trash carries no item.");
    if (changes.length >= MAX_OFFLINE_CHANGES) throw new OfflineRuleError("too_many", TOO_MANY_TEXT);
    return [...changes, { id: newId(), ...incoming, item: incoming.kind === "trash" ? null : incoming.item, sent, created_at: now, state: "waiting", reason: null }];
  }
  const old = changes[at] as OfflineChange;
  const fresh = { state: "waiting" as const, reason: null };
  let next: OfflineChange | null;
  if (old.kind === "trash") {
    if (incoming.kind !== "trash") throw new OfflineRuleError("trashed", TRASHED_OFFLINE_TEXT);
    next = old;
  } else if (incoming.kind === "trash") {
    if (old.kind === "create") next = old.sent ? { ...old, ...fresh, kind: "trash", base_revision: null, item: null } : null;
    else next = { ...old, ...fresh, kind: "trash", item: null };
  } else {
    // create + edit stays a create; edit + edit keeps the first base revision.
    next = { ...old, ...fresh, item: incoming.item };
  }
  const out = [...changes];
  if (next) out[at] = next;
  else out.splice(at, 1);
  return out;
}

/** The change for `itemId`, if there is one. */
export const changeFor = (changes: readonly OfflineChange[], itemId: string) => changes.find((c) => c.item_id === itemId);

// ------------------------------------------------------------ showing it

export interface Marker {
  changeId: string;
  kind: ChangeKind;
  state: ChangeState;
  /** "Waiting to sync", "Not sent: <reason>", "Changed on another device". */
  text: string;
}

export function markerText(c: Pick<OfflineChange, "state" | "reason">): string {
  if (c.state === "conflict") return CONFLICT_MARK;
  if (c.state === "held") return `Not sent: ${c.reason ?? "PassAuth couldn't send this change."}`;
  return WAITING_MARK;
}

export const markerOf = (c: OfflineChange): Marker => ({ changeId: c.id, kind: c.kind, state: c.state, text: markerText(c) });

/**
 * The offline copy with the list on top: created items appear (or replace the copy's when it already holds them),
 * edits show the new content (an edited item the copy no longer has is shown too, so it can be decided), trashed items
 * go (the extension never shows the trash). `make`: an entry for an item the copy doesn't hold (null: not shown, e.g.
 * its vault isn't open). `markers`: every change, by item id.
 */
export function overlay<E extends { id: string; vaultId: string; item: Item }>(
  entries: readonly E[],
  changes: readonly OfflineChange[],
  make: (c: OfflineChange) => E | null,
): { entries: E[]; markers: Map<string, Marker> } {
  const markers = new Map<string, Marker>();
  if (!changes.length) return { entries: [...entries], markers };
  const byItem = new Map(changes.map((c) => [c.item_id, c]));
  const out: E[] = [];
  const placed = new Set<string>();
  for (const e of entries) {
    const c = byItem.get(e.id);
    if (!c) {
      out.push(e);
      continue;
    }
    placed.add(e.id);
    if (c.kind === "trash") continue;
    out.push({ ...e, item: c.item as Item });
  }
  for (const c of changes) {
    markers.set(c.item_id, markerOf(c));
    if (c.kind === "trash" || placed.has(c.item_id)) continue;
    const made = make(c);
    if (made) out.push(made);
  }
  return { entries: out, markers };
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** The sync status line: "N changes waiting to sync" / "N changes need your decision" (both when both). */
export function statusOf(changes: readonly OfflineChange[]): { waiting: number; decide: number; text: string | null } {
  const decide = changes.filter((c) => c.state === "conflict").length;
  const waiting = changes.length - decide;
  const parts = [
    ...(waiting ? [plural(waiting, "change waiting to sync", "changes waiting to sync")] : []),
    ...(decide ? [plural(decide, "change needs your decision", "changes need your decision")] : []),
  ];
  return { waiting, decide, text: parts.length ? parts.join(" · ") : null };
}

// ------------------------------------------------------------ sending

/** Whether a failed request got no answer from the server (no network, DNS, refused/reset, TLS, timeout) or 502/503/504. */
export function isOfflineError(e: unknown): boolean {
  if (!e || typeof e !== "object") return false;
  const { code, status } = e as { code?: unknown; status?: unknown };
  if (code === "unreachable") return true;
  return status === 502 || status === 503 || status === 504;
}

/** The server's row for the item as the checked copy holds it (`data`: null for a trashed row sent as a summary). */
export interface ServerRow {
  revision: number;
  data: string | null;
  trashed: boolean;
}

/** Whether the change's vault can be written into after this sync's checks: "wait" while no checked answer covers it. */
export type VaultStanding = "ok" | "wait" | { hold: string };

export type SendAction =
  | { do: "wait" }
  | { do: "hold"; reason: string }
  | { do: "done" }
  | { do: "conflict"; reason: string }
  | { do: "create" }
  | { do: "new-id" }
  | { do: "update"; revision: number }
  | { do: "trash"; revision: number };

/**
 * What to do with one change now. `row`: the server's row from the checked copy (null: none). `serverIsMine()`: the
 * server's item, decrypted, has this change's content (asked only when its data is the data last sent).
 * - create: no row → create; the row holds what was sent → done (or an edit, when the item was changed since); another
 *   row under this id → a new id.
 * - edit: no row (deleted for good) or in the trash → conflict "deleted"; at `base_revision` → update over it; holds
 *   what was sent → done (or update); otherwise → conflict.
 * - trash: no row or in the trash → done; at `base_revision`, or holding what was sent → trash; otherwise → conflict.
 */
export function decideSend(change: OfflineChange, vault: VaultStanding, row: ServerRow | null, serverIsMine: () => boolean): SendAction {
  if (change.state === "conflict") return { do: "wait" };
  if (vault === "wait") return { do: "wait" };
  if (vault !== "ok") return { do: "hold", reason: vault.hold };
  const sentHere = !!change.sent && !!row && row.data !== null && row.data === change.sent.data;
  if (change.kind === "create") {
    if (!row) return { do: "create" };
    if (sentHere) return serverIsMine() ? { do: "done" } : { do: "update", revision: row.revision };
    // Moved to the trash on another device after this create reached the server.
    if (row.trashed && change.sent) return { do: "done" };
    return { do: "new-id" };
  }
  if (change.kind === "edit") {
    if (!row || row.trashed) return { do: "conflict", reason: DELETED_REASON };
    if (change.base_revision !== null && row.revision === change.base_revision) return { do: "update", revision: row.revision };
    if (sentHere) return serverIsMine() ? { do: "done" } : { do: "update", revision: row.revision };
    return { do: "conflict", reason: CHANGED_REASON };
  }
  if (!row || row.trashed) return { do: "done" };
  if ((change.base_revision !== null && row.revision === change.base_revision) || sentHere) return { do: "trash", revision: row.revision };
  return { do: "conflict", reason: CHANGED_REASON };
}

export type AfterError = { do: "stop" } | { do: "redecide" } | { do: "retry" } | { do: "exists" } | { do: "hold"; reason: string };

/**
 * After a failed request: no answer → stop (try later); `revision_conflict` → sync and decide again; a manifest or key
 * refusal → sync and send again; `item_exists` on a create → look at the stored row; anything else → held with the
 * app's words for it (`message`).
 */
export function afterSendError(e: unknown, kind: ChangeKind, message: string): AfterError {
  if (isOfflineError(e)) return { do: "stop" };
  const code = e && typeof e === "object" ? (e as { code?: unknown }).code : undefined;
  if (code === "revision_conflict") return { do: "redecide" };
  if (code === "manifest_conflict" || code === "manifest_required" || code === "vault_key_changed") return { do: "retry" };
  if (code === "item_exists" && kind === "create") return { do: "exists" };
  return { do: "hold", reason: message };
}

// ------------------------------------------------------------ conflicts

export type ConflictKind = "edit" | "deleted" | "trash";

/** Which decision sheet a change in conflict gets: its kind and the server's row now. */
export function conflictKind(change: Pick<OfflineChange, "kind">, row: ServerRow | null): ConflictKind {
  if (change.kind === "trash") return "trash";
  return !row || row.trashed ? "deleted" : "edit";
}

export type Resolution = "mine" | "other" | "both" | "new" | "discard" | "trash";

export interface ResolutionChoice {
  id: Resolution;
  title: string;
  sub: string;
}

export const RESOLUTIONS: Record<ConflictKind, ResolutionChoice[]> = {
  edit: [
    { id: "mine", title: "Keep mine", sub: "Your version replaces the other device's." },
    { id: "other", title: "Keep the other", sub: "Your change is dropped." },
    { id: "both", title: "Keep both", sub: "Yours is saved as a new item named “(offline copy)”." },
  ],
  deleted: [
    { id: "new", title: "Save mine as a new item", sub: "Your version is added again." },
    { id: "discard", title: "Discard mine", sub: "Your change is dropped." },
  ],
  trash: [
    { id: "trash", title: "Move to trash anyway", sub: "The other device's version goes to the trash." },
    { id: "other", title: "Keep the other", sub: "The item stays as the other device left it." },
  ],
};

/**
 * The list after the user's choice for `change` (in conflict): Keep mine = an edit over the server's current row;
 * Keep the other / Discard mine = removed; Keep both = mine as a new item (new id, name + " (offline copy)") in the same
 * vault; Save mine as a new item = the same without the suffix; Move to trash anyway = a trash at the current revision.
 * Throws when the choice doesn't fit the conflict, or the server's row needed for it is gone (sync and decide again).
 */
export function resolveConflict(change: OfflineChange, choice: Resolution, row: ServerRow | null, newId: () => string): OfflineChange | null {
  const kind = conflictKind(change, row);
  if (!RESOLUTIONS[kind].some((r) => r.id === choice)) throw new Error("That choice doesn't fit this change.");
  const fresh = { state: "waiting" as const, reason: null, sent: null };
  switch (choice) {
    case "other":
    case "discard":
      return null;
    case "mine":
      if (!row || row.trashed || !change.item) throw new Error(DELETED_REASON);
      return { ...change, ...fresh, kind: "edit", base_revision: row.revision };
    case "both":
    case "new": {
      if (!change.item) throw new Error("There is no version of yours to keep.");
      const name = choice === "both" ? `${change.item.name || "Untitled"}${OFFLINE_COPY_SUFFIX}` : change.item.name;
      return { ...change, ...fresh, kind: "create", item_id: newId(), base_revision: null, item: { ...change.item, name } };
    }
    case "trash":
      // Already gone on the server: nothing left to move.
      if (!row || row.trashed) return null;
      return { ...change, ...fresh, base_revision: row.revision };
  }
}

/** One line of the decision sheet's comparison. */
export interface FieldDiff {
  label: string;
  mine: string;
  theirs: string;
  /** Hidden until shown (passwords, codes, card numbers, hidden fields). */
  secret: boolean;
  differs: boolean;
}

function fieldsOf(i: Item | null): [string, string, boolean][] {
  if (!i) return [];
  const out: [string, string, boolean][] = [
    ["Name", i.name ?? "", false],
    ["Folder", i.folder ?? "", false],
    ["Favorite", i.favorite ? "Yes" : "", false],
  ];
  if (i.login) {
    out.push(["User name", i.login.username ?? "", false], ["Password", i.login.password ?? "", true]);
    out.push(["Websites", (i.login.urls ?? []).map((u) => u.url).join("\n"), false]);
    out.push(["Verification code key", i.login.totp ?? "", true]);
    const passkeys = i.login.passkeys?.length ?? 0;
    out.push(["Passkeys", passkeys ? String(passkeys) : "", false]);
  }
  if (i.card) {
    const c = i.card;
    out.push(
      ["Cardholder", c.cardholder_name ?? "", false],
      ["Card number", c.number ?? "", true],
      ["Expires", [c.exp_month, c.exp_year].filter(Boolean).join("/"), false],
      ["Security code", c.code ?? "", true],
    );
  }
  if (i.identity) {
    for (const [k, v] of Object.entries(i.identity)) if (typeof v === "string") out.push([k.replace(/_/g, " ").replace(/^./, (s) => s.toUpperCase()), v, false]);
  }
  if (i.ssh_key) out.push(["SSH key", JSON.stringify(i.ssh_key), true]);
  for (const f of i.fields ?? []) out.push([f.name || "Field", f.value ?? "", f.type === "hidden"]);
  out.push(["Notes", i.notes ?? "", false], ["Tags", (i.tags ?? []).join(", "), false]);
  return out;
}

/** Both versions field by field (labels in the order the item shows them), the differing ones marked; empty on both sides left out. */
export function compareItems(mine: Item | null, theirs: Item | null): FieldDiff[] {
  const a = fieldsOf(mine);
  const b = fieldsOf(theirs);
  const labels: string[] = [];
  for (const [l] of [...a, ...b]) if (!labels.includes(l)) labels.push(l);
  const pick = (list: [string, string, boolean][], l: string) => list.filter(([x]) => x === l);
  const out: FieldDiff[] = [];
  for (const label of labels) {
    const ma = pick(a, label);
    const mb = pick(b, label);
    const n = Math.max(ma.length, mb.length);
    for (let k = 0; k < n; k++) {
      const m = ma[k];
      const t = mb[k];
      const mine = m?.[1] ?? "";
      const theirs = t?.[1] ?? "";
      if (!mine && !theirs) continue;
      out.push({ label, mine, theirs, secret: !!(m?.[2] || t?.[2]), differs: mine !== theirs });
    }
  }
  return out;
}
