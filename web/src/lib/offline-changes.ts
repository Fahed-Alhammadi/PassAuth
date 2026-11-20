/**
 * Offline changes (waiting to sync): the pure rules of ARCHITECTURE "Offline changes". The list, how a new change is
 * merged into it, how it is shown on top of the vault, what the sender does with each change given the server's row,
 * how errors are judged and what each conflict answer does. No I/O here: `vault.ts` stores, seals and sends.
 */
import type { Item, VaultEntry } from "./types";

export type ChangeKind = "create" | "edit" | "trash";
export type ChangeState = "waiting" | "held" | "conflict";

/** The exact body of the last attempt that may have reached the server. */
export interface SentBody {
  key: string;
  data: string;
  key_epoch?: number | null;
}

export interface OfflineChange {
  id: string;
  kind: ChangeKind;
  vault_id: string;
  item_id: string;
  /** The server revision the change started from; null for a create. */
  base_revision: number | null;
  /** The decrypted item as the editor saved it (create/edit); null for a trash. */
  item: Item | null;
  sent: SentBody | null;
  /** Milliseconds. */
  created_at: number;
  state: ChangeState;
  /** Shown for held and conflict, else null. */
  reason: string | null;
}

export interface ChangeList {
  version: 1;
  changes: OfflineChange[];
}

export const LIST_VERSION = 1;
export const MAX_CHANGES = 500;
/** Sends at most this many times when the server answers that something moved meanwhile. */
export const MAX_TRIES = 3;

export const TOO_MANY_CHANGES = "Too many changes are waiting. Connect to the internet before making more.";
export const NEEDS_CONNECTION = "You're offline. This needs a connection.";
export const TRASHED_NO_EDIT = "This item is in the trash. Restoring it needs a connection.";
export const HAS_CHANGE =
  "This item has a change that hasn't been sent yet. Wait until it is sent, or open the item and decide about it first.";
export const WAITING_TEXT = "Waiting to sync";
export const CONFLICT_TEXT = "Changed on another device";
export const DELETED_TEXT = "Deleted on another device";
export const MOVED_TEXT = "Moved to another vault on another device";
export const DISCARD_TITLE = "Discard this change?";
export const DISCARD_BODY = "Your change to this item will be lost.";
export const DISCARD_ACTION = "Discard this change";
export const OFFLINE_COPY_SUFFIX = " (offline copy)";
export const LIST_UNREADABLE = "Changes waiting on this device can't be read.";
export const LIST_DROPPED = "Changes saved on this device earlier couldn't be opened with this account and were removed.";
export const HELD_VAULT_GONE = "The vault is no longer available.";
export const HELD_READ_ONLY = "You can no longer change this vault.";
export const HELD_VAULT_WARNING = "This vault has a warning. Check it before your change is sent.";

export const emptyList = (): ChangeList => ({ version: 1, changes: [] });

/** An error the user sees when a change can't go into the list. */
export class OfflineChangeError extends Error {}

// ------------------------------------------------------------------ reading

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const KINDS: readonly string[] = ["create", "edit", "trash"];
const STATES: readonly string[] = ["waiting", "held", "conflict"];

function readSent(v: unknown): SentBody | null | undefined {
  if (v === null || v === undefined) return null;
  if (!isObj(v) || typeof v.key !== "string" || typeof v.data !== "string") return undefined;
  const epoch = v.key_epoch;
  if (epoch !== undefined && epoch !== null && typeof epoch !== "number") return undefined;
  return { key: v.key, data: v.data, ...(epoch === undefined ? {} : { key_epoch: epoch }) };
}

function readChange(v: unknown): OfflineChange | null {
  if (!isObj(v)) return null;
  const { id, kind, vault_id, item_id, base_revision, item, created_at, state, reason } = v;
  if (typeof id !== "string" || !id || typeof kind !== "string" || !KINDS.includes(kind)) return null;
  if (typeof vault_id !== "string" || !vault_id || typeof item_id !== "string" || !item_id) return null;
  if (base_revision !== null && typeof base_revision !== "number") return null;
  if (kind === "create" && base_revision !== null) return null;
  if (kind === "trash" ? item !== null : !isObj(item) || typeof item.name !== "string") return null;
  if (typeof created_at !== "number" || typeof state !== "string" || !STATES.includes(state)) return null;
  if (reason !== null && typeof reason !== "string") return null;
  const sent = readSent(v.sent);
  if (sent === undefined) return null;
  return { id, kind: kind as ChangeKind, vault_id, item_id, base_revision, item: (item as unknown as Item) ?? null, sent, created_at, state: state as ChangeState, reason: reason ?? null };
}

/** The list from its JSON (as `openOfflineChanges` returns it). Changes that don't read are left out. */
export function parseList(json: string): ChangeList {
  const v: unknown = JSON.parse(json);
  if (!isObj(v) || v.version !== LIST_VERSION || !Array.isArray(v.changes)) throw new Error("unexpected offline change list");
  const changes: OfflineChange[] = [];
  const seen = new Set<string>();
  for (const raw of v.changes) {
    const c = readChange(raw);
    // One change per item: a second one for the same item can't be told apart, so only the first counts.
    if (c && !seen.has(c.item_id)) {
      seen.add(c.item_id);
      changes.push(c);
    }
  }
  return { version: 1, changes };
}

export const serializeList = (list: ChangeList): string => JSON.stringify(list);

export const changeFor = (list: ChangeList, itemId: string): OfflineChange | undefined => list.changes.find((c) => c.item_id === itemId);

// ------------------------------------------------------------------ merging

/** What the app wants to record: the change before it is merged with one the item may have already. */
export interface NewChange {
  id: string;
  kind: ChangeKind;
  vault_id: string;
  item_id: string;
  base_revision: number | null;
  item: Item | null;
  sent?: SentBody | null;
  created_at: number;
}

function fresh(c: NewChange): OfflineChange {
  return {
    id: c.id,
    kind: c.kind,
    vault_id: c.vault_id,
    item_id: c.item_id,
    base_revision: c.kind === "create" ? null : c.base_revision,
    item: c.kind === "trash" ? null : c.item,
    sent: c.sent ?? null,
    created_at: c.created_at,
    state: "waiting",
    reason: null,
  };
}

/**
 * The list with `next` added. One change per item: a change to an item that has one already is merged into it
 * (create + edit = create with the new item; edit + edit = edit with the first base revision and the newest item; edit
 * + trash = trash with the first base revision; create + trash = removed, or a trash with no base revision when it may
 * have reached the server; a trashed item can't be edited). A merged change waits again. A new change beyond
 * `MAX_CHANGES` is refused.
 */
export function mergeChange(list: ChangeList, next: NewChange): ChangeList {
  const at = list.changes.findIndex((c) => c.item_id === next.item_id);
  if (at < 0) {
    if (list.changes.length >= MAX_CHANGES) throw new OfflineChangeError(TOO_MANY_CHANGES);
    if (next.kind === "edit" && next.base_revision === null) throw new Error("an edit needs the revision it started from");
    return { version: 1, changes: [...list.changes, fresh(next)] };
  }
  const old = list.changes[at];
  const rest = (c: OfflineChange | null) => {
    const changes = [...list.changes];
    if (c) changes[at] = c;
    else changes.splice(at, 1);
    return { version: 1 as const, changes };
  };
  const waiting = { state: "waiting" as const, reason: null };
  if (old.kind === "trash") {
    if (next.kind === "trash") return rest({ ...old, ...waiting });
    throw new OfflineChangeError(TRASHED_NO_EDIT);
  }
  if (next.kind === "create") throw new Error("an item with a change can't be created again");
  if (next.kind === "edit") return rest({ ...old, item: next.item, vault_id: old.vault_id, ...waiting });
  // A trash.
  if (old.kind === "create") {
    if (!old.sent) return rest(null);
    return rest({ ...old, kind: "trash", base_revision: null, item: null, ...waiting });
  }
  return rest({ ...old, kind: "trash", item: null, ...waiting });
}

export const removeChange = (list: ChangeList, changeId: string): ChangeList => ({ version: 1, changes: list.changes.filter((c) => c.id !== changeId) });

export const replaceChange = (list: ChangeList, change: OfflineChange): ChangeList => ({
  version: 1,
  changes: list.changes.map((c) => (c.id === change.id ? change : c)),
});

// ------------------------------------------------------------------ sending

/** The server's row for the change's item, as the last checked sync holds it. */
export interface ServerRow {
  vault_id: string;
  revision: number;
  data: string;
  deleted_at: number | null;
}

export type SendStep =
  | { step: "post" }
  /** A create whose id is taken by another item: give it a new id once and post. */
  | { step: "new-id" }
  | { step: "put"; revision: number }
  | { step: "trash"; revision: number }
  /** Nothing (more) to send: the server already holds the change. */
  | { step: "done" }
  | { step: "conflict"; why: "changed" | "deleted" };

const sentHere = (c: OfflineChange, row: ServerRow) => !!c.sent && row.data === c.sent.data;

/** Deep equality of JSON values; a property that is undefined counts as missing. */
function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => sameValue(x, b[i]));
  }
  if (!isObj(a) || !isObj(b)) return false;
  const keys = (o: Record<string, unknown>) => Object.keys(o).filter((k) => o[k] !== undefined);
  const ka = keys(a);
  const kb = keys(b);
  return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && sameValue(a[k], b[k]));
}

/** Whether two versions of an item hold the same content (`rev` and `format` are set by the core, so they don't count). */
export function sameItem(a: Item | null, b: Item | null): boolean {
  if (!a || !b) return false;
  const content = (i: Item) => ({ ...i, rev: undefined, format: undefined });
  return sameValue(content(a), content(b));
}

/**
 * What to send for `change`, given the server's row for its item (null: the server has no such item) and that row's
 * decrypted item (`stored`; null when this device can't open it). A row holding the last attempt (`sent`) means that
 * attempt was stored; the change is done only when its item still equals the stored one, else (the user changed it
 * since) it goes on as an edit at the row's revision.
 */
export function decideSend(change: OfflineChange, row: ServerRow | null, stored: Item | null = null): SendStep {
  const landed = (r: ServerRow): SendStep => (sameItem(change.item, stored) ? { step: "done" } : { step: "put", revision: r.revision });
  switch (change.kind) {
    case "create":
      if (!row) return { step: "post" };
      return sentHere(change, row) ? landed(row) : { step: "new-id" };
    case "edit":
      if (!row) return { step: "conflict", why: "deleted" };
      if (row.revision === change.base_revision) return { step: "put", revision: row.revision };
      if (sentHere(change, row)) return landed(row);
      return { step: "conflict", why: "changed" };
    case "trash":
      if (!row || row.deleted_at !== null) return { step: "done" };
      // An attempt of this device's that was stored before the trash (create or edit + trash) counts as the start too.
      if (row.revision === change.base_revision || sentHere(change, row)) return { step: "trash", revision: row.revision };
      return { step: "conflict", why: "changed" };
  }
}

/** Why a change can't be sent into its vault now (it is held), or null when it can. */
export function holdReason(vault: { writable: boolean; warning: boolean } | null): string | null {
  if (!vault) return HELD_VAULT_GONE;
  if (vault.warning) return HELD_VAULT_WARNING;
  if (!vault.writable) return HELD_READ_ONLY;
  return null;
}

/** A failed request, described without its classes (pure). */
export interface Failure {
  /** No answer from the server: no network, DNS, refused or reset, TLS, timeout. */
  unreachable?: boolean;
  status?: number;
  code?: string;
}

export type FailureKind =
  /** No answer: the change waits, the run stops and is tried later. */
  | "offline"
  /** The item changed meanwhile: sync and decide again. */
  | "revision"
  /** The vault changed meanwhile (manifest, key): sync and try again. */
  | "retry"
  /** A create's id exists already. */
  | "exists"
  /** Any other answer: held with the app's wording. */
  | "other";

export function classifyFailure(f: Failure): FailureKind {
  if (f.unreachable || f.status === 502 || f.status === 503 || f.status === 504) return "offline";
  if (f.code === "revision_conflict") return "revision";
  if (f.code === "manifest_conflict" || f.code === "manifest_required" || f.code === "vault_key_changed") return "retry";
  if (f.code === "item_exists") return "exists";
  return "other";
}

/** Whether a save that failed this way goes into the list instead (no answer, or 502/503/504). */
export const waitsAfter = (f: Failure): boolean => classifyFailure(f) === "offline";

// ------------------------------------------------------------------ conflicts

export type ConflictKind = "edit" | "deleted" | "trash";

/**
 * Which decision sheet a conflict gets: by the change's kind, and whether the server still has the item in the change's
 * vault (an edit of an item moved to another vault gets the "deleted" sheet: Keep mine there would only conflict again).
 */
export function conflictKind(change: OfflineChange, row: ServerRow | null): ConflictKind | null {
  if (change.kind === "trash") return "trash";
  if (change.kind === "edit") return row && row.vault_id === change.vault_id ? "edit" : "deleted";
  return null;
}

export type Resolution = "keep-mine" | "keep-other" | "keep-both" | "save-new" | "discard" | "trash-anyway";

export const RESOLUTIONS: Record<ConflictKind, Resolution[]> = {
  edit: ["keep-mine", "keep-other", "keep-both"],
  deleted: ["save-new", "discard"],
  trash: ["trash-anyway", "keep-other"],
};

export const RESOLUTION_TEXT: Record<Resolution, { title: string; sub: string }> = {
  "keep-mine": { title: "Keep mine", sub: "Your version replaces the other one." },
  "keep-other": { title: "Keep the other", sub: "Your change on this device is dropped." },
  "keep-both": { title: "Keep both", sub: `Yours is saved as a new item, named with "${OFFLINE_COPY_SUFFIX.trim()}".` },
  "save-new": { title: "Save mine as a new item", sub: "The item was deleted. Yours is saved as a new item." },
  discard: { title: "Discard mine", sub: "Your change on this device is dropped." },
  "trash-anyway": { title: "Move to trash anyway", sub: "The other version goes to the trash." },
};

/**
 * The list after the user's answer to a conflict (nothing is sent before they answer). `row` is the server's current
 * row for the item; `newId` an item id for answers that save a new item. Keep mine / Move to trash anyway start again
 * from the server's current revision; Keep both / Save mine as a new item turn the change into a create in the same
 * vault; Keep the other / Discard mine remove it.
 */
export function resolveConflict(list: ChangeList, changeId: string, answer: Resolution, row: ServerRow | null, newId: string): ChangeList {
  const c = list.changes.find((x) => x.id === changeId);
  if (!c) return list;
  const kind = conflictKind(c, row);
  if (!kind || !RESOLUTIONS[kind].includes(answer)) throw new Error("This answer doesn't fit this change.");
  const again = { state: "waiting" as const, reason: null, sent: null };
  switch (answer) {
    case "keep-other":
    case "discard":
      return removeChange(list, changeId);
    case "keep-mine":
    case "trash-anyway":
      if (!row) return removeChange(list, changeId);
      // Move to trash anyway follows an item moved to another vault meanwhile (it is held there if it can't go).
      return replaceChange(list, { ...c, ...again, base_revision: row.revision, vault_id: row.vault_id });
    case "keep-both":
    case "save-new": {
      const item = c.item as Item;
      const named = answer === "keep-both" ? { ...item, name: `${item.name}${OFFLINE_COPY_SUFFIX}` } : item;
      return replaceChange(list, { ...c, ...again, kind: "create", item_id: newId, base_revision: null, item: named });
    }
  }
}

// ------------------------------------------------------------------ showing

export interface Marker {
  state: ChangeState;
  text: string;
}

export function markerOf(c: OfflineChange): Marker {
  if (c.state === "held") return { state: "held", text: `Not sent: ${c.reason ?? "try again later."}` };
  if (c.state === "conflict") return { state: "conflict", text: c.reason === DELETED_TEXT || c.reason === MOVED_TEXT ? c.reason : CONFLICT_TEXT };
  return { state: "waiting", text: WAITING_TEXT };
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many.replace("N", String(n)));

/** The sync status lines: changes waiting (waiting or held), and those that need a decision. */
export function statusLines(list: ChangeList): { waiting: string | null; decisions: string | null } {
  const decisions = list.changes.filter((c) => c.state === "conflict").length;
  const waiting = list.changes.length - decisions;
  return {
    waiting: waiting ? plural(waiting, "1 change waiting to sync", "N changes waiting to sync") : null,
    decisions: decisions ? plural(decisions, "1 change needs your decision", "N changes need your decision") : null,
  };
}

/** The warning before the list is deleted (sign-out, change server, delete account); n unknown while locked. */
export function lostText(n: number | null): string {
  if (n === null) return "Changes made on this device haven't been sent and will be lost.";
  return plural(n, "1 change hasn't been sent and will be lost.", "N changes haven't been sent and will be lost.");
}

/**
 * The vault's items with the list applied on top: created items appear, edits show the new content, trashed items
 * are in the trash. An edit whose item the server no longer has is shown from the change (so it can be decided).
 * `vaults`: the vaults shown (changes into others aren't). The result is sorted with `compare`.
 */
export function overlay(items: readonly VaultEntry[], list: ChangeList, vaults: ReadonlySet<string>, compare: (a: VaultEntry, b: VaultEntry) => number): VaultEntry[] {
  if (!list.changes.length) return items as VaultEntry[];
  const byItem = new Map(list.changes.map((c) => [c.item_id, c]));
  const out: VaultEntry[] = [];
  const shown = new Set<string>();
  for (const e of items) {
    const c = byItem.get(e.id);
    shown.add(e.id);
    if (!c) out.push(e);
    else if (c.kind === "trash") out.push({ ...e, deletedAt: e.deletedAt ?? Math.max(1, Math.floor(c.created_at / 1000)) });
    else if (c.item) out.push({ ...e, item: c.item });
    else out.push(e);
  }
  for (const c of list.changes) {
    if (shown.has(c.item_id) || !c.item || !vaults.has(c.vault_id)) continue;
    out.push({ id: c.item_id, item: c.item, vaultId: c.vault_id, revision: 0, deletedAt: null, enc: { id: c.item_id, vault_id: c.vault_id, key: "", data: "" } });
  }
  return out.sort(compare);
}

// ------------------------------------------------------------------ differences

export interface FieldDiff {
  label: string;
  mine: string;
  other: string;
  secret: boolean;
  differs: boolean;
}

/** The fields of both versions, in the item page's order, with the ones that differ marked. */
export function diffFields(mine: Item | null, other: Item | null): FieldDiff[] {
  const rows: FieldDiff[] = [];
  const add = (label: string, a: string | undefined | null, b: string | undefined | null, secret = false) => {
    const x = a ?? "";
    const y = b ?? "";
    if (!x && !y) return;
    rows.push({ label, mine: x, other: y, secret, differs: x !== y });
  };
  add("Name", mine?.name, other?.name);
  add("Username", mine?.login?.username, other?.login?.username);
  add("Password", mine?.login?.password, other?.login?.password, true);
  add("Websites", mine?.login?.urls.map((u) => u.url).filter(Boolean).join("\n"), other?.login?.urls.map((u) => u.url).filter(Boolean).join("\n"));
  add("Verification code", mine?.login?.totp, other?.login?.totp, true);
  add("Cardholder name", mine?.card?.cardholder_name, other?.card?.cardholder_name);
  add("Card number", mine?.card?.number, other?.card?.number, true);
  const exp = (i: Item | null) => (i?.card && (i.card.exp_month || i.card.exp_year) ? `${i.card.exp_month}/${i.card.exp_year}` : "");
  add("Expires", exp(mine), exp(other));
  add("Security code", mine?.card?.code, other?.card?.code, true);
  const person = (i: Item | null) => (i?.identity ? [i.identity.title, i.identity.first_name, i.identity.middle_name, i.identity.last_name].filter(Boolean).join(" ") : "");
  add("Full name", person(mine), person(other));
  add("Email", mine?.identity?.email, other?.identity?.email);
  add("Phone", mine?.identity?.phone, other?.identity?.phone);
  const address = (i: Item | null) =>
    i?.identity ? [i.identity.address1, i.identity.address2, i.identity.city, i.identity.state, i.identity.postal_code, i.identity.country].filter(Boolean).join(", ") : "";
  add("Address", address(mine), address(other));
  add("Public key", mine?.ssh_key?.public_key, other?.ssh_key?.public_key);
  add("Private key", mine?.ssh_key?.private_key, other?.ssh_key?.private_key, true);
  add("Notes", mine?.notes, other?.notes);
  add("Folder", mine?.folder, other?.folder);
  const names = [...new Set([...(mine?.fields ?? []), ...(other?.fields ?? [])].map((f) => f.name))];
  for (const name of names) {
    const a = mine?.fields.find((f) => f.name === name);
    const b = other?.fields.find((f) => f.name === name);
    add(name || "Field", a?.value, b?.value, a?.type === "hidden" || b?.type === "hidden");
  }
  return rows;
}
