import { describe, expect, it } from "vitest";
import {
  CONFLICT_TEXT,
  DELETED_TEXT,
  MOVED_TEXT,
  HELD_READ_ONLY,
  HELD_VAULT_GONE,
  HELD_VAULT_WARNING,
  MAX_CHANGES,
  OfflineChangeError,
  TOO_MANY_CHANGES,
  TRASHED_NO_EDIT,
  WAITING_TEXT,
  classifyFailure,
  conflictKind,
  decideSend,
  diffFields,
  emptyList,
  holdReason,
  lostText,
  markerOf,
  mergeChange,
  overlay,
  parseList,
  removeChange,
  resolveConflict,
  sameItem,
  serializeList,
  statusLines,
  waitsAfter,
  type ChangeList,
  type NewChange,
  type OfflineChange,
  type ServerRow,
} from "./offline-changes";
import { emptyItem, type Item, type VaultEntry } from "./types";

const item = (name: string, password = "pw"): Item => {
  const i = emptyItem("login");
  i.name = name;
  i.login!.password = password;
  return i;
};

let n = 0;
const make = (kind: NewChange["kind"], over: Partial<NewChange> = {}): NewChange => ({
  id: `c${++n}`,
  kind,
  vault_id: "v1",
  item_id: "i1",
  base_revision: kind === "create" ? null : 5,
  item: kind === "trash" ? null : item("A"),
  created_at: 1000 * n,
  ...over,
});
const add = (list: ChangeList, ...changes: NewChange[]) => changes.reduce(mergeChange, list);
const only = (list: ChangeList): OfflineChange => {
  expect(list.changes).toHaveLength(1);
  return list.changes[0];
};
const row = (over: Partial<ServerRow> = {}): ServerRow => ({ vault_id: "v1", revision: 5, data: "D", deleted_at: null, ...over });
const sent = (data = "D") => ({ key: "K", data, key_epoch: 0 });

describe("list format", () => {
  it("round-trips through JSON and keeps the contract's field names", () => {
    const list = add(emptyList(), make("create", { item_id: "a", sent: sent() }), make("edit", { item_id: "b" }));
    const json = serializeList(list);
    const raw = JSON.parse(json);
    expect(raw.version).toBe(1);
    expect(Object.keys(raw.changes[0]).sort()).toEqual(["base_revision", "created_at", "id", "item", "item_id", "kind", "reason", "sent", "state", "vault_id"]);
    expect(parseList(json)).toEqual(list);
  });

  it("refuses another version and leaves out changes that don't read or repeat an item", () => {
    expect(() => parseList(JSON.stringify({ version: 2, changes: [] }))).toThrow();
    const good = only(add(emptyList(), make("edit")));
    const json = JSON.stringify({ version: 1, changes: [good, { ...good, id: "dup" }, { ...good, item_id: "x", kind: "nope" }, { ...good, item_id: "y", base_revision: "1" }] });
    expect(parseList(json).changes).toEqual([good]);
  });
});

describe("merging (one change per item)", () => {
  it("create + edit = create with the new item (the last attempt is kept: the sender compares it with the server)", () => {
    const c = only(add(emptyList(), make("create", { sent: sent() }), make("edit", { item: item("B") })));
    expect(c.kind).toBe("create");
    expect(c.base_revision).toBeNull();
    expect(c.item?.name).toBe("B");
    expect(c.sent).toEqual(sent());
    // The first attempt landed: the edit merged after it is still sent, at the stored row's revision.
    expect(decideSend(c, row({ revision: 7 }), item("A"))).toEqual({ step: "put", revision: 7 });
  });

  it("edit + edit = edit with the first base revision and the newest item", () => {
    const c = only(add(emptyList(), make("edit", { base_revision: 3 }), make("edit", { base_revision: 9, item: item("C") })));
    expect(c).toMatchObject({ kind: "edit", base_revision: 3, item: { name: "C" } });
  });

  it("edit + trash = trash with the first base revision", () => {
    const c = only(add(emptyList(), make("edit", { base_revision: 3 }), make("trash", { base_revision: 9 })));
    expect(c).toMatchObject({ kind: "trash", base_revision: 3, item: null });
  });

  it("create + trash removes the change unless it may have reached the server", () => {
    expect(add(emptyList(), make("create"), make("trash", { base_revision: null })).changes).toEqual([]);
    const c = only(add(emptyList(), make("create", { sent: sent("S") }), make("trash", { base_revision: null })));
    expect(c).toMatchObject({ kind: "trash", base_revision: null, item: null, sent: { data: "S" } });
  });

  it("a trashed item can't be edited offline; trash + trash stays a trash", () => {
    const list = add(emptyList(), make("trash"));
    expect(() => mergeChange(list, make("edit"))).toThrow(TRASHED_NO_EDIT);
    expect(only(mergeChange(list, make("trash"))).kind).toBe("trash");
  });

  it("a merged change waits again", () => {
    const list = add(emptyList(), make("edit"));
    const held: ChangeList = { version: 1, changes: [{ ...list.changes[0], state: "conflict", reason: CONFLICT_TEXT }] };
    expect(only(mergeChange(held, make("edit")))).toMatchObject({ state: "waiting", reason: null });
  });

  it("keeps changes to other items apart, oldest first", () => {
    const list = add(emptyList(), make("edit", { item_id: "a" }), make("create", { item_id: "b" }), make("edit", { item_id: "a", item: item("Z") }));
    expect(list.changes.map((c) => c.item_id)).toEqual(["a", "b"]);
  });

  it("refuses the 501st change, but still merges into one it has", () => {
    let list = emptyList();
    for (let i = 0; i < MAX_CHANGES; i++) list = mergeChange(list, make("edit", { item_id: `i${i}` }));
    expect(() => mergeChange(list, make("edit", { item_id: "new" }))).toThrow(OfflineChangeError);
    expect(() => mergeChange(list, make("edit", { item_id: "new" }))).toThrow(TOO_MANY_CHANGES);
    expect(mergeChange(list, make("edit", { item_id: "i7" })).changes).toHaveLength(MAX_CHANGES);
  });

  it("removes a change (Discard this change)", () => {
    const list = add(emptyList(), make("edit", { item_id: "a" }), make("edit", { item_id: "b" }));
    expect(removeChange(list, list.changes[0].id).changes.map((c) => c.item_id)).toEqual(["b"]);
  });
});

describe("sending", () => {
  const c = (kind: NewChange["kind"], over: Partial<OfflineChange> = {}): OfflineChange => ({ ...only(add(emptyList(), make(kind))), ...over });

  it("create: post when the server has no such id, done when it holds what was sent, else a new id", () => {
    expect(decideSend(c("create"), null)).toEqual({ step: "post" });
    expect(decideSend(c("create", { sent: sent("D") }), row(), item("A"))).toEqual({ step: "done" });
    expect(decideSend(c("create", { sent: sent("X") }), row())).toEqual({ step: "new-id" });
    expect(decideSend(c("create"), row())).toEqual({ step: "new-id" });
  });

  it("edit: conflict 'deleted' when gone, put at the base revision, done when it holds what was sent, else conflict", () => {
    expect(decideSend(c("edit"), null)).toEqual({ step: "conflict", why: "deleted" });
    expect(decideSend(c("edit", { base_revision: 5 }), row())).toEqual({ step: "put", revision: 5 });
    expect(decideSend(c("edit", { base_revision: 4, sent: sent("D") }), row(), item("A"))).toEqual({ step: "done" });
    expect(decideSend(c("edit", { base_revision: 4 }), row())).toEqual({ step: "conflict", why: "changed" });
  });

  it("trash: done when gone or in the trash, trash at the base revision or over what was sent, else conflict", () => {
    expect(decideSend(c("trash"), null)).toEqual({ step: "done" });
    expect(decideSend(c("trash"), row({ deleted_at: 99 }))).toEqual({ step: "done" });
    expect(decideSend(c("trash", { base_revision: 5 }), row())).toEqual({ step: "trash", revision: 5 });
    expect(decideSend(c("trash", { base_revision: null, sent: sent("D") }), row({ revision: 8 }))).toEqual({ step: "trash", revision: 8 });
    expect(decideSend(c("trash", { base_revision: 3, sent: sent("D") }), row({ revision: 8 }))).toEqual({ step: "trash", revision: 8 });
    expect(decideSend(c("trash", { base_revision: 3 }), row())).toEqual({ step: "conflict", why: "changed" });
    expect(decideSend(c("trash", { base_revision: null }), row())).toEqual({ step: "conflict", why: "changed" });
  });

  it("a landed attempt ends the change only when the change still holds what was stored", () => {
    const stored = { ...item("A"), rev: 4, format: 3 };
    // Same content: rev and format (set by the core) don't count.
    expect(decideSend(c("create", { sent: sent("D") }), row({ revision: 2 }), stored)).toEqual({ step: "done" });
    expect(decideSend(c("edit", { base_revision: 1, sent: sent("D") }), row({ revision: 2 }), stored)).toEqual({ step: "done" });
    // Changed since (merged after the attempt): an edit at the stored row's revision.
    expect(decideSend(c("create", { sent: sent("D"), item: item("B") }), row({ revision: 2 }), stored)).toEqual({ step: "put", revision: 2 });
    expect(decideSend(c("edit", { base_revision: 1, sent: sent("D"), item: item("A", "new") }), row({ revision: 2 }), stored)).toEqual({ step: "put", revision: 2 });
    // The stored row can't be opened here: never taken as done.
    expect(decideSend(c("create", { sent: sent("D") }), row({ revision: 2 }), null)).toEqual({ step: "put", revision: 2 });
    // create → landed → trash: trashed at the stored row's revision.
    const trashed = only(add(emptyList(), make("create", { sent: sent("D") }), make("trash", { base_revision: null })));
    expect(decideSend(trashed, row({ revision: 2 }))).toEqual({ step: "trash", revision: 2 });
  });

  it("compares items by content, ignoring rev, format and missing vs undefined fields", () => {
    expect(sameItem(item("A"), { ...item("A"), rev: 9, format: 1 })).toBe(true);
    expect(sameItem(item("A"), { ...item("A"), notes: "x" })).toBe(false);
    expect(sameItem(item("A"), item("A", "other"))).toBe(false);
    expect(sameItem({ ...item("A"), extra: undefined } as Item, item("A"))).toBe(true);
    expect(sameItem(item("A"), null)).toBe(false);
  });

  it("holds a change whose vault is gone, read-only or has a warning", () => {
    expect(holdReason(null)).toBe(HELD_VAULT_GONE);
    expect(holdReason({ writable: false, warning: false })).toBe(HELD_READ_ONLY);
    expect(holdReason({ writable: true, warning: true })).toBe(HELD_VAULT_WARNING);
    expect(holdReason({ writable: true, warning: false })).toBeNull();
  });

  it("judges failures: no answer and 502/503/504 wait; revision, vault and id races; anything else is held", () => {
    expect(classifyFailure({ unreachable: true })).toBe("offline");
    for (const status of [502, 503, 504]) expect(classifyFailure({ status })).toBe("offline");
    expect(classifyFailure({ status: 409, code: "revision_conflict" })).toBe("revision");
    expect(classifyFailure({ status: 409, code: "manifest_conflict" })).toBe("retry");
    expect(classifyFailure({ status: 409, code: "vault_key_changed" })).toBe("retry");
    expect(classifyFailure({ status: 409, code: "item_exists" })).toBe("exists");
    for (const status of [400, 403, 404, 413, 429, 500, 507]) expect(classifyFailure({ status, code: "x" })).toBe("other");
  });

  it("puts a save in the list only after no answer or 502/503/504", () => {
    expect(waitsAfter({ unreachable: true })).toBe(true);
    expect(waitsAfter({ status: 503 })).toBe(true);
    expect(waitsAfter({ status: 500 })).toBe(false);
    expect(waitsAfter({ status: 507 })).toBe(false);
    expect(waitsAfter({ status: 409, code: "revision_conflict" })).toBe(false);
  });
});

describe("conflicts", () => {
  const change = (kind: NewChange["kind"]) => add(emptyList(), make(kind, { item: kind === "trash" ? null : item("Mine") }));

  it("classifies by kind and whether the server still has the item", () => {
    expect(conflictKind(change("edit").changes[0], row())).toBe("edit");
    expect(conflictKind(change("edit").changes[0], null)).toBe("deleted");
    expect(conflictKind(change("trash").changes[0], row())).toBe("trash");
    expect(conflictKind(change("create").changes[0], null)).toBeNull();
    // Moved to another vault: Keep mine there would only conflict again, so it gets the "deleted" sheet.
    expect(conflictKind(change("edit").changes[0], row({ vault_id: "v2" }))).toBe("deleted");
    expect(conflictKind(change("trash").changes[0], row({ vault_id: "v2" }))).toBe("trash");
  });

  it("Move to trash anyway follows an item moved to another vault", () => {
    const list = change("trash");
    expect(only(resolveConflict(list, list.changes[0].id, "trash-anyway", row({ vault_id: "v2", revision: 4 }), "x"))).toMatchObject({ vault_id: "v2", base_revision: 4 });
    const edit = change("edit");
    expect(() => resolveConflict(edit, edit.changes[0].id, "keep-mine", row({ vault_id: "v2" }), "x")).toThrow();
    expect(only(resolveConflict(edit, edit.changes[0].id, "save-new", row({ vault_id: "v2" }), "n3"))).toMatchObject({ kind: "create", item_id: "n3", vault_id: "v1" });
  });

  it("Keep mine sends an edit at the server's current revision; Keep the other removes it", () => {
    const list = change("edit");
    const id = list.changes[0].id;
    const conflicted: ChangeList = { version: 1, changes: [{ ...list.changes[0], state: "conflict", reason: CONFLICT_TEXT, sent: sent() }] };
    expect(only(resolveConflict(conflicted, id, "keep-mine", row({ revision: 12 }), "new"))).toMatchObject({ kind: "edit", base_revision: 12, state: "waiting", reason: null, sent: null });
    expect(resolveConflict(conflicted, id, "keep-other", row(), "new").changes).toEqual([]);
  });

  it("Keep both saves mine as a new item in the same vault, named as the offline copy", () => {
    const list = change("edit");
    const c = only(resolveConflict(list, list.changes[0].id, "keep-both", row(), "new-id"));
    expect(c).toMatchObject({ kind: "create", item_id: "new-id", vault_id: "v1", base_revision: null, sent: null, state: "waiting" });
    expect(c.item?.name).toBe("Mine (offline copy)");
  });

  it("deleted elsewhere: Save mine as a new item, or Discard mine", () => {
    const list = change("edit");
    const id = list.changes[0].id;
    expect(only(resolveConflict(list, id, "save-new", null, "n2"))).toMatchObject({ kind: "create", item_id: "n2", item: { name: "Mine" } });
    expect(resolveConflict(list, id, "discard", null, "n2").changes).toEqual([]);
    expect(() => resolveConflict(list, id, "keep-mine", null, "n2")).toThrow();
  });

  it("trash: Move to trash anyway at the current revision, or Keep the other", () => {
    const list = change("trash");
    const id = list.changes[0].id;
    expect(only(resolveConflict(list, id, "trash-anyway", row({ revision: 20 }), "x"))).toMatchObject({ kind: "trash", base_revision: 20 });
    expect(resolveConflict(list, id, "keep-other", row(), "x").changes).toEqual([]);
    expect(() => resolveConflict(list, id, "keep-both", row(), "x")).toThrow();
  });

  it("marks the fields that differ, passwords marked secret", () => {
    const rows = diffFields(item("Same", "one"), item("Same", "two"));
    expect(rows.find((r) => r.label === "Name")).toMatchObject({ differs: false });
    expect(rows.find((r) => r.label === "Password")).toMatchObject({ differs: true, secret: true });
    expect(diffFields(item("A"), null).find((r) => r.label === "Name")).toMatchObject({ mine: "A", other: "", differs: true });
  });
});

describe("showing", () => {
  const entry = (id: string, name: string, over: Partial<VaultEntry> = {}): VaultEntry => ({
    id,
    item: item(name),
    vaultId: "v1",
    revision: 1,
    deletedAt: null,
    enc: { id, vault_id: "v1", key: "k", data: "d" },
    ...over,
  });
  const byName = (a: VaultEntry, b: VaultEntry) => a.item.name.localeCompare(b.item.name);

  it("applies creates, edits and trashes on top of the copy", () => {
    const list = add(
      emptyList(),
      make("create", { item_id: "new", item: item("Bee") }),
      make("edit", { item_id: "e", item: item("Zed edited") }),
      make("trash", { item_id: "t" }),
      make("create", { item_id: "elsewhere", vault_id: "hidden", item: item("Hidden") }),
    );
    const shown = overlay([entry("e", "Zed"), entry("t", "Tea"), entry("x", "Ant")], list, new Set(["v1"]), byName);
    expect(shown.map((e) => e.item.name)).toEqual(["Ant", "Bee", "Tea", "Zed edited"]);
    expect(shown.find((e) => e.id === "t")!.deletedAt).not.toBeNull();
    expect(shown.find((e) => e.id === "e")!.revision).toBe(1);
  });

  it("shows an edit whose item is gone from the server, so it can be decided", () => {
    const list = add(emptyList(), make("edit", { item_id: "gone", item: item("Kept") }));
    expect(overlay([], list, new Set(["v1"]), byName).map((e) => e.id)).toEqual(["gone"]);
  });

  it("markers and the sync status", () => {
    const list = add(emptyList(), make("edit", { item_id: "a" }), make("edit", { item_id: "b" }), make("edit", { item_id: "c" }));
    list.changes[1] = { ...list.changes[1], state: "held", reason: "This is larger than your server allows." };
    list.changes[2] = { ...list.changes[2], state: "conflict", reason: DELETED_TEXT };
    expect(markerOf(list.changes[0])).toEqual({ state: "waiting", text: WAITING_TEXT });
    expect(markerOf(list.changes[1]).text).toBe("Not sent: This is larger than your server allows.");
    expect(markerOf(list.changes[2]).text).toBe(DELETED_TEXT);
    expect(markerOf({ ...list.changes[2], reason: MOVED_TEXT }).text).toBe(MOVED_TEXT);
    expect(statusLines(list)).toEqual({ waiting: "2 changes waiting to sync", decisions: "1 change needs your decision" });
    expect(statusLines(emptyList())).toEqual({ waiting: null, decisions: null });
  });

  it("words the warning before the list is lost", () => {
    expect(lostText(1)).toBe("1 change hasn't been sent and will be lost.");
    expect(lostText(3)).toBe("3 changes haven't been sent and will be lost.");
    expect(lostText(null)).toMatch(/will be lost/);
  });
});
