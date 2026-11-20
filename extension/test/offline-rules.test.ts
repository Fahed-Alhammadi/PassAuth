// Offline changes, the pure rules (background/offline-rules.ts; ARCHITECTURE "Offline changes"): reading the list,
// one change per item (every merge rule), the 500 limit, the overlay on the offline copy and its markers, the status
// line, which failures wait, the send decision for each kind, what an error means, conflict kinds and every choice.

import type { Item } from "@web/lib/types";
import { expect, test } from "vitest";
import {
  afterSendError,
  CHANGED_REASON,
  compareItems,
  conflictKind,
  DELETED_REASON,
  decideSend,
  isOfflineError,
  lostText,
  MAX_OFFLINE_CHANGES,
  markerText,
  mergeChange,
  type NewChange,
  type OfflineChange,
  OfflineRuleError,
  overlay,
  parseList,
  RESOLUTIONS,
  resolveConflict,
  type ServerRow,
  serializeList,
  statusOf,
  TOO_MANY_TEXT,
} from "../src/background/offline-rules";

const item = (name: string, over: Partial<Item> = {}): Item => ({
  name,
  notes: "",
  favorite: false,
  folder: null,
  tags: [],
  login: { username: "u", password: "p", urls: [], totp: null, passkeys: [] },
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 1,
  updated_at: 1,
  ...over,
});

let ids = 0;
const newId = () => `c${++ids}`;
const change = (over: Partial<OfflineChange> = {}): OfflineChange => ({
  id: "c0",
  kind: "edit",
  vault_id: "v1",
  item_id: "i1",
  base_revision: 5,
  item: item("A"),
  sent: null,
  created_at: 100,
  state: "waiting",
  reason: null,
  ...over,
});
const incoming = (over: Partial<NewChange> = {}): NewChange => ({ kind: "edit", vault_id: "v1", item_id: "i1", base_revision: 5, item: item("B"), ...over });
const row = (over: Partial<ServerRow> = {}): ServerRow => ({ revision: 5, data: "d5", trashed: false, ...over });
const sent = { key: "k", data: "mine", key_epoch: 1 };
const never = () => {
  throw new Error("not asked");
};

// ------------------------------------------------------------ the list

test("the list round-trips; malformed changes, a second change for the same item and unknown states are dropped", () => {
  const list = { version: 1, changes: [change(), change({ id: "c9", kind: "trash", item: null, item_id: "i2", sent })] };
  expect(parseList(serializeList(list))).toEqual(list);
  const raw = JSON.stringify({
    version: 1,
    changes: [
      change(),
      change({ id: "dup" }),
      { ...change({ item_id: "i3" }), state: "sending" },
      { ...change({ item_id: "i4" }), kind: "trash" },
      { ...change({ item_id: "i5" }), sent: { key: 1 } },
      "x",
    ],
  });
  expect(parseList(raw)?.changes.map((c) => c.id)).toEqual(["c0"]);
  expect(parseList("not json"), "not readable: kept, not an empty list").toBeNull();
  expect(parseList("{}")).toBeNull();
  expect(parseList(JSON.stringify({ version: 2, changes: [] })), "a newer version").toBeNull();
});

// ------------------------------------------------------------ one change per item

test("a first change is added as waiting, with the attempt's body when one may have reached the server", () => {
  const out = mergeChange([], incoming({ kind: "create", base_revision: null }), 7, () => "n1", sent);
  expect(out).toEqual([{ id: "n1", kind: "create", vault_id: "v1", item_id: "i1", base_revision: null, item: item("B"), sent, created_at: 7, state: "waiting", reason: null }]);
});

test("create + edit = create with the new item", () => {
  const out = mergeChange([change({ kind: "create", base_revision: null, sent })], incoming({ item: item("New") }), 9, newId);
  expect(out).toHaveLength(1);
  expect(out[0]).toMatchObject({ kind: "create", base_revision: null, item: { name: "New" }, sent, created_at: 100 });
});

test("edit + edit = edit with the first base revision and the newest item", () => {
  const out = mergeChange([change({ base_revision: 5 })], incoming({ base_revision: 8, item: item("Newest") }), 9, newId);
  expect(out[0]).toMatchObject({ kind: "edit", base_revision: 5, item: { name: "Newest" } });
});

test("edit + trash = trash with the first base revision", () => {
  const out = mergeChange([change({ base_revision: 5 })], incoming({ kind: "trash", base_revision: 8, item: null }), 9, newId);
  expect(out[0]).toMatchObject({ kind: "trash", base_revision: 5, item: null });
});

test("create + trash: removed (nothing reaches the server), unless it was sent: then a trash with no base and `sent` kept", () => {
  expect(mergeChange([change({ kind: "create", base_revision: null })], incoming({ kind: "trash", base_revision: null, item: null }), 9, newId)).toEqual([]);
  const out = mergeChange([change({ kind: "create", base_revision: null, sent })], incoming({ kind: "trash", base_revision: null, item: null }), 9, newId);
  expect(out[0]).toMatchObject({ kind: "trash", base_revision: null, item: null, sent });
});

test("a trashed item can't be edited offline; trash + trash changes nothing", () => {
  const trashed = change({ kind: "trash", item: null });
  expect(() => mergeChange([trashed], incoming(), 9, newId)).toThrow(OfflineRuleError);
  expect(mergeChange([trashed], incoming({ kind: "trash", item: null }), 9, newId)).toEqual([trashed]);
});

test("a merged change is decided again: held or in conflict becomes waiting", () => {
  const out = mergeChange([change({ state: "held", reason: "x" }), change({ id: "c2", item_id: "i2", state: "conflict", reason: CHANGED_REASON })], incoming(), 9, newId);
  expect(out[0]).toMatchObject({ state: "waiting", reason: null });
  const out2 = mergeChange(out, incoming({ item_id: "i2" }), 9, newId);
  expect(out2[1]).toMatchObject({ state: "waiting", reason: null });
});

test("at most 500 changes: the next new one is refused with the contract's words; merges still work", () => {
  const full = Array.from({ length: MAX_OFFLINE_CHANGES }, (_, n) => change({ id: `c${n}`, item_id: `i${n}` }));
  try {
    mergeChange(full, incoming({ item_id: "new" }), 9, newId);
    throw new Error("no throw");
  } catch (e) {
    expect(e).toBeInstanceOf(OfflineRuleError);
    expect((e as Error).message).toBe(TOO_MANY_TEXT);
  }
  expect(mergeChange(full, incoming({ item_id: "i3" }), 9, newId)).toHaveLength(MAX_OFFLINE_CHANGES);
});

// ------------------------------------------------------------ showing it

test("overlay: created items appear, edits show the new content, trashed items go, an edit of an item the copy lost is shown", () => {
  const entries = [
    { id: "i1", vaultId: "v1", item: item("Old") },
    { id: "i2", vaultId: "v1", item: item("Bin") },
    { id: "i3", vaultId: "v1", item: item("Same") },
  ];
  const changes = [
    change({ item_id: "i1", item: item("Edited") }),
    change({ id: "c2", item_id: "i2", kind: "trash", item: null }),
    change({ id: "c3", item_id: "n1", kind: "create", base_revision: null, item: item("Created") }),
    change({ id: "c4", item_id: "gone", item: item("Lost"), state: "conflict", reason: DELETED_REASON }),
  ];
  const { entries: shown, markers } = overlay(entries, changes, (c) => ({ id: c.item_id, vaultId: c.vault_id, item: c.item as Item }));
  expect(shown.map((e) => [e.id, e.item.name])).toEqual([
    ["i1", "Edited"],
    ["i3", "Same"],
    ["n1", "Created"],
    ["gone", "Lost"],
  ]);
  expect(markers.get("i1")?.text).toBe("Waiting to sync");
  expect(markers.get("i2")?.kind).toBe("trash");
  expect(markers.get("gone")?.text).toBe("Changed on another device");
  expect(markers.has("i3")).toBe(false);
  // An item whose vault isn't open isn't shown.
  expect(overlay([], [changes[2] as OfflineChange], () => null).entries).toEqual([]);
});

test("markers: waiting, held with its reason, conflict", () => {
  expect(markerText({ state: "waiting", reason: null })).toBe("Waiting to sync");
  expect(markerText({ state: "held", reason: "The vault is gone." })).toBe("Not sent: The vault is gone.");
  expect(markerText({ state: "conflict", reason: CHANGED_REASON })).toBe("Changed on another device");
});

test("the sync status counts waiting (held included) and decisions; the leaving warning", () => {
  expect(statusOf([]).text).toBeNull();
  expect(statusOf([change()]).text).toBe("1 change waiting to sync");
  expect(statusOf([change(), change({ state: "held" }), change({ state: "conflict" }), change({ state: "conflict" })])).toEqual({
    waiting: 2,
    decide: 2,
    text: "2 changes waiting to sync · 2 changes need your decision",
  });
  expect(statusOf([change({ state: "conflict" })]).text).toBe("1 change needs your decision");
  expect(lostText(1)).toBe("1 change hasn't been sent and will be lost.");
  expect(lostText(3)).toBe("3 changes haven't been sent and will be lost.");
});

// ------------------------------------------------------------ when a change waits

test("only failures without an answer (and 502/503/504) wait; every other answer is shown", () => {
  expect(isOfflineError({ code: "unreachable" })).toBe(true);
  for (const status of [502, 503, 504]) expect(isOfflineError({ code: "unavailable", status })).toBe(true);
  for (const status of [400, 403, 404, 409, 429, 500, 507]) expect(isOfflineError({ code: "x", status })).toBe(false);
  expect(isOfflineError(new Error("boom"))).toBe(false);
  expect(isOfflineError(null)).toBe(false);
});

// ------------------------------------------------------------ sending

test("the vault decides first: not checked yet → wait; gone, read-only or with a warning → held; a conflict waits for the user", () => {
  expect(decideSend(change(), "wait", row(), never)).toEqual({ do: "wait" });
  expect(decideSend(change(), { hold: "gone" }, row(), never)).toEqual({ do: "hold", reason: "gone" });
  expect(decideSend(change({ state: "conflict" }), "ok", row(), never)).toEqual({ do: "wait" });
});

test("create: no row → create; the row holds what was sent → done (or an edit when changed since); another row → a new id", () => {
  const c = change({ kind: "create", base_revision: null });
  expect(decideSend(c, "ok", null, never)).toEqual({ do: "create" });
  const s = change({ kind: "create", base_revision: null, sent });
  expect(decideSend(s, "ok", row({ data: "mine", revision: 3 }), () => true)).toEqual({ do: "done" });
  expect(decideSend(s, "ok", row({ data: "mine", revision: 3 }), () => false)).toEqual({ do: "update", revision: 3 });
  expect(decideSend(s, "ok", row({ data: "other" }), never)).toEqual({ do: "new-id" });
  expect(decideSend(c, "ok", row({ data: "other" }), never)).toEqual({ do: "new-id" });
  expect(decideSend(s, "ok", row({ data: null, trashed: true }), never)).toEqual({ do: "done" });
});

test("edit: gone or trashed → conflict 'deleted'; at the base revision → update; holds what was sent → done/update; else conflict", () => {
  expect(decideSend(change(), "ok", null, never)).toEqual({ do: "conflict", reason: DELETED_REASON });
  expect(decideSend(change(), "ok", row({ trashed: true, data: null }), never)).toEqual({ do: "conflict", reason: DELETED_REASON });
  expect(decideSend(change({ base_revision: 5 }), "ok", row({ revision: 5 }), never)).toEqual({ do: "update", revision: 5 });
  expect(decideSend(change({ sent }), "ok", row({ revision: 6, data: "mine" }), () => true)).toEqual({ do: "done" });
  expect(decideSend(change({ sent }), "ok", row({ revision: 6, data: "mine" }), () => false)).toEqual({ do: "update", revision: 6 });
  expect(decideSend(change(), "ok", row({ revision: 6 }), never)).toEqual({ do: "conflict", reason: CHANGED_REASON });
});

test("trash: gone or already trashed → done; at the base revision (or holding what was sent) → trash; else conflict", () => {
  const t = change({ kind: "trash", item: null });
  expect(decideSend(t, "ok", null, never)).toEqual({ do: "done" });
  expect(decideSend(t, "ok", row({ trashed: true, data: null }), never)).toEqual({ do: "done" });
  expect(decideSend(t, "ok", row({ revision: 5 }), never)).toEqual({ do: "trash", revision: 5 });
  expect(decideSend(change({ kind: "trash", item: null, base_revision: null, sent }), "ok", row({ revision: 9, data: "mine" }), never)).toEqual({ do: "trash", revision: 9 });
  expect(decideSend(t, "ok", row({ revision: 7 }), never)).toEqual({ do: "conflict", reason: CHANGED_REASON });
});

test("after an error: no answer stops; revision conflict decides again; manifest/key refusals retry; item_exists on a create; else held", () => {
  expect(afterSendError({ code: "unreachable" }, "edit", "m")).toEqual({ do: "stop" });
  expect(afterSendError({ code: "x", status: 503 }, "edit", "m")).toEqual({ do: "stop" });
  expect(afterSendError({ code: "revision_conflict", status: 409 }, "edit", "m")).toEqual({ do: "redecide" });
  for (const code of ["manifest_conflict", "manifest_required", "vault_key_changed"]) expect(afterSendError({ code, status: 409 }, "trash", "m")).toEqual({ do: "retry" });
  expect(afterSendError({ code: "item_exists", status: 409 }, "create", "m")).toEqual({ do: "exists" });
  expect(afterSendError({ code: "item_exists", status: 409 }, "edit", "m")).toEqual({ do: "hold", reason: "m" });
  expect(afterSendError({ code: "quota_exceeded", status: 403 }, "create", "Storage limit.")).toEqual({ do: "hold", reason: "Storage limit." });
  expect(afterSendError({ code: "error", status: 500 }, "create", "Server.")).toEqual({ do: "hold", reason: "Server." });
});

// ------------------------------------------------------------ conflicts

test("conflict kinds: edit, edit of a deleted (or trashed) item, trash", () => {
  expect(conflictKind({ kind: "edit" }, row())).toBe("edit");
  expect(conflictKind({ kind: "edit" }, null)).toBe("deleted");
  expect(conflictKind({ kind: "edit" }, row({ trashed: true }))).toBe("deleted");
  expect(conflictKind({ kind: "trash" }, row())).toBe("trash");
  expect(RESOLUTIONS.edit.map((r) => r.title)).toEqual(["Keep mine", "Keep the other", "Keep both"]);
  expect(RESOLUTIONS.deleted.map((r) => r.title)).toEqual(["Save mine as a new item", "Discard mine"]);
  expect(RESOLUTIONS.trash.map((r) => r.title)).toEqual(["Move to trash anyway", "Keep the other"]);
});

test("Keep mine: an edit over the server's current row; Keep the other: removed; Keep both: a new item '(offline copy)'", () => {
  const c = change({ state: "conflict", reason: CHANGED_REASON, sent, item: item("Mine") });
  expect(resolveConflict(c, "mine", row({ revision: 9 }), newId)).toMatchObject({ kind: "edit", base_revision: 9, state: "waiting", reason: null, sent: null, item_id: "i1" });
  expect(resolveConflict(c, "other", row({ revision: 9 }), newId)).toBeNull();
  const both = resolveConflict(c, "both", row({ revision: 9 }), () => "fresh");
  expect(both).toMatchObject({ kind: "create", item_id: "fresh", vault_id: "v1", base_revision: null, sent: null, state: "waiting", item: { name: "Mine (offline copy)" } });
  // A choice of another sheet is refused.
  expect(() => resolveConflict(c, "trash", row(), newId)).toThrow();
});

test("deleted on another device: Save mine as a new item / Discard mine", () => {
  const c = change({ state: "conflict", reason: DELETED_REASON, item: item("Mine") });
  expect(resolveConflict(c, "new", null, () => "fresh")).toMatchObject({ kind: "create", item_id: "fresh", item: { name: "Mine" }, state: "waiting" });
  expect(resolveConflict(c, "discard", null, newId)).toBeNull();
  expect(() => resolveConflict(c, "mine", null, newId)).toThrow();
});

test("trash: Move to trash anyway at the current revision / Keep the other", () => {
  const c = change({ kind: "trash", item: null, state: "conflict", reason: CHANGED_REASON });
  expect(resolveConflict(c, "trash", row({ revision: 12 }), newId)).toMatchObject({ kind: "trash", base_revision: 12, state: "waiting" });
  expect(resolveConflict(c, "other", row({ revision: 12 }), newId)).toBeNull();
});

test("the comparison marks the differing fields and hides secrets; empty on both sides is left out", () => {
  const mine = item("Bank", { login: { username: "me", password: "new", urls: [{ url: "https://bank.example", match: "default" }], totp: null, passkeys: [] } });
  const theirs = item("Bank", { notes: "pin in drawer", login: { username: "me", password: "old", urls: [{ url: "https://bank.example", match: "default" }], totp: null, passkeys: [] } });
  const diff = compareItems(mine, theirs);
  expect(diff.find((d) => d.label === "Password")).toEqual({ label: "Password", mine: "new", theirs: "old", secret: true, differs: true });
  expect(diff.find((d) => d.label === "User name")?.differs).toBe(false);
  expect(diff.find((d) => d.label === "Notes")).toMatchObject({ mine: "", theirs: "pin in drawer", differs: true });
  expect(diff.some((d) => d.label === "Folder")).toBe(false);
  // Only the server's side (a trash conflict): every field is "different".
  expect(compareItems(null, theirs).every((d) => d.differs)).toBe(true);
});
