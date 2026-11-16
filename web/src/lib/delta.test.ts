import { describe, expect, it } from "vitest";
import {
  afterWrite,
  applyOwnWrite,
  DeltaError,
  knownSeq,
  mergeSync,
  noticeAction,
  sameCiphertext,
  vaultKeyChanged,
  type Snapshot,
} from "./delta";
import type { SyncItemRow, SyncResponse, SyncVaultRow } from "./types";

// ------------------------------------------------------------------ helpers

const USER = { id: "user-1", email: "alex@example.com", name: "Alex", email_verified: true };
const BUNDLE = { account_id: "acct-1", kdf: {}, secret_key_enabled: false };

function vault(id: string, seq: number, extra: Partial<SyncVaultRow> = {}): SyncVaultRow {
  return { id, meta: `meta-${id}`, role: "owner", wrapped_key: `wk-${id}`, key_kind: "account", key_epoch: 0, seq, ...extra };
}

function row(id: string, vaultId: string, data = `data-${id}`, extra: Partial<SyncItemRow> = {}): SyncItemRow {
  return { id, vault_id: vaultId, item_key: `key-${id}`, data, revision: 1, deleted_at: null, created_at: 1, updated_at: 1, ...extra };
}

function full(vaults: SyncVaultRow[], items: SyncItemRow[], cursor = "c1", revision = 10): SyncResponse {
  return { revision, cursor, user: USER, bundle: BUNDLE, vaults, items };
}

function delta(
  vaults: SyncVaultRow[],
  items: SyncItemRow[],
  more: { deleted?: { id: string; vault_id: string }[]; reset?: string[]; cursor?: string; revision?: number } = {},
): SyncResponse {
  return {
    revision: more.revision ?? 20,
    cursor: more.cursor ?? "c2",
    user: USER,
    bundle: BUNDLE,
    vaults,
    items,
    deleted: more.deleted ?? [],
    reset: more.reset ?? [],
    delta: true,
  };
}

function snap(resp: SyncResponse): Snapshot {
  const m = mergeSync(null, resp);
  if (!m) throw new Error("no snapshot");
  return m.snapshot;
}

function merge(prev: Snapshot, resp: SyncResponse) {
  const m = mergeSync(prev, resp);
  if (!m) throw new Error("delta not applied");
  return m;
}

/** Item id → vault id, sorted, to compare whole snapshots at a glance. */
const placement = (s: Snapshot) => Object.fromEntries([...s.items.values()].map((r) => [r.id, r.vault_id]).sort());

// ------------------------------------------------------------------- merges

describe("mergeSync", () => {
  it("replaces everything with an answer that isn't a delta", () => {
    const first = snap(full([vault("A", 3)], [row("x", "A"), row("y", "A")]));
    const m = merge(first, full([vault("A", 5), vault("B", 1)], [row("z", "B")], "c9", 30));
    expect(placement(m.snapshot)).toEqual({ z: "B" });
    expect(m.snapshot.cursor).toBe("c9");
    expect(m.snapshot.revision).toBe(30);
    expect(m.behind).toBe(false);
  });

  it("keeps no cursor when the server sends none", () => {
    const s = snap({ revision: 1, user: USER, bundle: BUNDLE, vaults: [vault("A", 0, { seq: undefined })], items: [] });
    expect(s.cursor).toBeNull();
    expect(knownSeq(s, "A")).toBeUndefined();
  });

  it("applies deleted first, then upserts by id", () => {
    const prev = snap(full([vault("A", 3)], [row("x", "A"), row("y", "A"), row("z", "A")]));
    const m = merge(
      prev,
      delta([vault("A", 6)], [row("y", "A", "y-edited"), row("n", "A")], { deleted: [{ id: "x", vault_id: "A" }, { id: "gone", vault_id: "A" }] }),
    );
    expect(placement(m.snapshot)).toEqual({ n: "A", y: "A", z: "A" });
    expect(m.snapshot.items.get("y")?.data).toBe("y-edited");
    // Rows the delta didn't touch are the same objects (their decrypted copies are reused).
    expect(m.snapshot.items.get("z")).toBe(prev.items.get("z"));
    expect(m.snapshot.cursor).toBe("c2");
  });

  it("re-adds an item deleted and saved again under the same id", () => {
    const prev = snap(full([vault("A", 3)], [row("x", "A")]));
    const m = merge(prev, delta([vault("A", 5)], [row("x", "A", "x-again")], { deleted: [{ id: "x", vault_id: "A" }] }));
    expect(m.snapshot.items.get("x")?.data).toBe("x-again");
  });

  it("moves an item between two readable vaults", () => {
    const prev = snap(full([vault("A", 3), vault("B", 7)], [row("x", "A"), row("y", "B")]));
    const m = merge(prev, delta([vault("A", 4), vault("B", 8)], [row("x", "B", "x-in-B")], { deleted: [{ id: "x", vault_id: "A" }] }));
    expect(placement(m.snapshot)).toEqual({ x: "B", y: "B" });
    expect(m.snapshot.items.get("x")?.data).toBe("x-in-B");
  });

  it("keeps an item that moved away and back: the tombstone names the vault it left last", () => {
    // A → B → A after the cursor: B has the tombstone, A the item (its tombstone went when the item came back).
    const prev = snap(full([vault("A", 3), vault("B", 7)], [row("x", "A")]));
    const m = merge(prev, delta([vault("A", 5), vault("B", 9)], [row("x", "A", "x-back")], { deleted: [{ id: "x", vault_id: "B" }] }));
    expect(placement(m.snapshot)).toEqual({ x: "A" });
    expect(m.snapshot.items.get("x")?.data).toBe("x-back");
  });

  it("ignores a tombstone for a vault the local copy isn't in", () => {
    const prev = snap(full([vault("A", 3), vault("B", 7)], [row("x", "A")]));
    const m = merge(prev, delta([vault("A", 3), vault("B", 8)], [], { deleted: [{ id: "x", vault_id: "B" }] }));
    expect(placement(m.snapshot)).toEqual({ x: "A" });
  });

  it("drops an item moved to a vault the account can't read", () => {
    const prev = snap(full([vault("A", 3)], [row("x", "A")]));
    const m = merge(prev, delta([vault("A", 4)], [], { deleted: [{ id: "x", vault_id: "A" }] }));
    expect(m.snapshot.items.size).toBe(0);
  });

  it("replaces every item of a reset vault and leaves the other vaults alone", () => {
    const prev = snap(full([vault("A", 3), vault("B", 2)], [row("a1", "A"), row("a2", "A"), row("b1", "B")]));
    const m = merge(prev, delta([vault("A", 50), vault("B", 2)], [row("a2", "A", "a2-new"), row("a3", "A")], { reset: ["A"] }));
    expect(placement(m.snapshot)).toEqual({ a2: "A", a3: "A", b1: "B" });
    expect(m.snapshot.items.get("b1")).toBe(prev.items.get("b1"));
  });

  it("empties a reset vault the answer sends no items for", () => {
    const prev = snap(full([vault("A", 3)], [row("a1", "A")]));
    const m = merge(prev, delta([vault("A", 9)], [], { reset: ["A"] }));
    expect(m.snapshot.items.size).toBe(0);
  });

  it("drops a vault the account lost, with its items", () => {
    const prev = snap(full([vault("A", 3), vault("S", 4, { key_kind: "sealed", role: "write" })], [row("a", "A"), row("s1", "S"), row("s2", "S")]));
    const m = merge(prev, delta([vault("A", 3)], []));
    expect(placement(m.snapshot)).toEqual({ a: "A" });
    expect(m.snapshot.vaults.map((v) => v.id)).toEqual(["A"]);
  });

  it("adds a vault shared with the account (sent whole as a reset)", () => {
    const prev = snap(full([vault("A", 3)], [row("a", "A")]));
    const m = merge(prev, delta([vault("A", 3), vault("N", 12, { key_kind: "sealed" })], [row("n1", "N")], { reset: ["N"] }));
    expect(placement(m.snapshot)).toEqual({ a: "A", n1: "N" });
  });

  it("takes a vault's new key with the reset that comes with it", () => {
    const before = vault("A", 3);
    const after = vault("A", 4, { key_epoch: 1, wrapped_key: "wk-A-2" });
    expect(vaultKeyChanged(before, after)).toBe(true);
    expect(vaultKeyChanged(before, { ...before, seq: 99, meta: "renamed", role: "admin", rotation_pending: 1 })).toBe(false);
    expect(vaultKeyChanged(before, { ...before, key_kind: "sealed" })).toBe(true);
    const prev = snap(full([before], [row("a1", "A")]));
    const m = merge(prev, delta([after], [row("a1", "A", "a1-under-new-key")], { reset: ["A"] }));
    expect(m.snapshot.vaults[0]).toBe(after);
    expect(m.snapshot.items.get("a1")?.data).toBe("a1-under-new-key");
  });

  it("refuses a delta without a base or for another account", () => {
    expect(mergeSync(null, delta([vault("A", 1)], []))).toBeNull();
    const prev = snap(full([vault("A", 1)], []));
    expect(mergeSync(prev, { ...delta([vault("A", 1)], []), user: { ...USER, id: "someone-else" } })).toBeNull();
  });

  it("throws on a malformed delta", () => {
    const prev = snap(full([vault("A", 1)], []));
    const bad: unknown[] = [
      { ...delta([vault("A", 2)], []), deleted: "x" },
      { ...delta([vault("A", 2)], []), deleted: [{ id: 1, vault_id: "A" }] },
      { ...delta([vault("A", 2)], []), reset: [7] },
      { ...delta([vault("A", 2)], []), cursor: 5 },
      delta([vault("A", 2)], [{ ...row("x", "A"), id: undefined as unknown as string }]),
      delta([{ ...vault("A", 2), seq: "2" as unknown as number }], []),
    ];
    for (const b of bad) expect(() => mergeSync(prev, b as SyncResponse)).toThrow(DeltaError);
  });

  it("refuses vault rows and users whose fields would reach the core or the screen with the wrong type", () => {
    const prev = snap(full([vault("A", 1)], []));
    const huge = { length: 900000000 };
    const rows = [
      { wrapped_key: huge },
      { wrapped_key: 7 },
      { key_kind: null },
      { meta: {} },
      { role: ["owner"] },
      { key_epoch: "1" },
      { rotation_pending: true },
      { id: "" },
    ].map((x) => ({ ...vault("A", 2), ...x }) as unknown as SyncVaultRow);
    for (const v of rows) {
      // A delta: the caller then fetches everything; a full answer: a sync error. Never a crash, nothing reaches the core.
      expect(() => mergeSync(prev, delta([v], []))).toThrow(DeltaError);
      expect(() => mergeSync(null, full([v], []))).toThrow(DeltaError);
    }
    for (const user of [{ ...USER, email: huge }, { ...USER, name: 3 }, { ...USER, email_verified: "yes" }, null])
      expect(() => mergeSync(null, { ...full([vault("A", 1)], []), user } as unknown as SyncResponse)).toThrow(DeltaError);
    expect(() => mergeSync(null, { ...full([vault("A", 1)], []), bundle: { account_id: 5 } } as unknown as SyncResponse)).toThrow(DeltaError);
    // Fields older servers leave out are fine.
    const old = { id: "A", meta: "m", role: "owner", wrapped_key: "wk", key_kind: "account" } as SyncVaultRow;
    expect(mergeSync(null, full([old], []))?.snapshot.vaults).toEqual([old]);
  });

  it("drops items the answer puts in a vault it doesn't list", () => {
    const prev = snap(full([vault("A", 1)], []));
    const m = merge(prev, delta([vault("A", 2)], [row("x", "A"), row("stray", "Z")]));
    expect(placement(m.snapshot)).toEqual({ x: "A" });
  });
});

// ------------------------------------------------------------- own writes

describe("own writes", () => {
  it("decides from the write's vault number", () => {
    expect(afterWrite(5, 6, true)).toBe("apply");
    expect(afterWrite(5, 6, false)).toBe("sync");
    expect(afterWrite(5, 5, true)).toBe("none"); // a sync already brought it
    expect(afterWrite(5, 3, true)).toBe("none"); // out of order: older than what is here
    expect(afterWrite(5, 8, true)).toBe("sync"); // other writes in between
    expect(afterWrite(undefined, 6, true)).toBe("sync"); // no delta sync
    expect(afterWrite(5, undefined, true)).toBe("sync"); // an older server's answer
    expect(afterWrite(5, "6", true)).toBe("sync");
  });

  it("shows an own write, and the next answer is merged over it", () => {
    const prev = snap(full([vault("A", 5)], [row("x", "A")]));
    const shown = applyOwnWrite(prev, { kind: "upsert", vaultSeq: 6, row: row("n", "A", "n-sent") });
    expect(knownSeq(shown, "A")).toBe(6);
    expect(shown.cursor).toBe(prev.cursor); // still behind the write
    expect(placement(shown)).toEqual({ n: "A", x: "A" });
    // The next delta (from the old cursor) carries the write again, as stored.
    const m = merge(shown, delta([vault("A", 6)], [row("n", "A", "n-stored")]));
    expect(m.behind).toBe(false);
    expect(m.snapshot.own).toEqual({});
    expect(m.snapshot.items.get("n")?.data).toBe("n-stored");
    expect(knownSeq(m.snapshot, "A")).toBe(6);
  });

  it("removes an item deleted for good only from its vault", () => {
    const prev = snap(full([vault("A", 5), vault("B", 2)], [row("x", "A"), row("y", "B")]));
    const shown = applyOwnWrite(prev, { kind: "remove", id: "x", vaultId: "A", vaultSeq: 6 });
    expect(placement(shown)).toEqual({ y: "B" });
    expect(applyOwnWrite(prev, { kind: "remove", id: "y", vaultId: "A", vaultSeq: 6 }).items.has("y")).toBe(true);
  });

  it("flags an answer older than a write it showed (out-of-order numbers)", () => {
    const prev = snap(full([vault("A", 5)], [row("x", "A")]));
    const shown = applyOwnWrite(prev, { kind: "upsert", vaultSeq: 6, row: row("x", "A", "x-mine") });
    const stale = merge(shown, delta([vault("A", 5)], []));
    expect(stale.behind).toBe(true);
    expect(merge(shown, delta([vault("A", 7)], [row("x", "A", "x-theirs")])).behind).toBe(false);
    // A vault that is gone has nothing left to protect.
    expect(merge(shown, delta([], [])).behind).toBe(false);
  });
});

// ------------------------------------------------------------ live messages

describe("live-sync messages", () => {
  const known = (table: Record<string, number>) => (id: string) => table[id];
  const have = known({ A: 5, B: 9 });

  it("syncs only for a vault number newer than this client's", () => {
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 6 } }, have, 40, true)).toBe("sync");
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 5 } }, have, 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 4, B: 9 } }, have, 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 5, B: 10 } }, have, 40, true)).toBe("sync");
  });

  it("syncs for a vault it doesn't know (shared with the account, or created elsewhere)", () => {
    expect(noticeAction({ type: "sync", revision: 50, vaults: { N: 0 } }, have, 40, true)).toBe("sync");
  });

  it("skips what the last answer already covers, also a vault it no longer has", () => {
    // The vault was deleted here and the sync after it read revision 50: its message (revision 50) brings nothing.
    expect(noticeAction({ type: "sync", revision: 50, vaults: { Gone: 7 } }, have, 50, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 49, vaults: { A: 99 } }, have, 50, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 51, vaults: { Gone: 7 } }, have, 50, true)).toBe("sync");
  });

  it("judges own writes shown without asking by the vault numbers (the revision stays behind them)", () => {
    // Two own writes in A shown locally (A now 7); the last answer read revision 40.
    expect(noticeAction({ type: "sync", revision: 61, vaults: { A: 7 }, origin: "mine" }, known({ A: 7 }), 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 62, vaults: { A: 8 }, origin: "mine" }, known({ A: 7 }), 40, true)).toBe("sync");
  });

  it("ignores the origin: another tab of this session shares it", () => {
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 6 }, origin: "mine" }, have, 40, true)).toBe("sync");
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 5 }, origin: "mine" }, have, 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: 5 }, origin: "theirs" }, have, 40, true)).toBe("skip");
  });

  it("syncs for profile and account changes when the revision is newer", () => {
    expect(noticeAction({ type: "sync", revision: 50, vaults: {} }, have, 40, true)).toBe("sync");
    expect(noticeAction({ type: "sync", revision: 40, vaults: {} }, have, 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync", revision: 39, vaults: {} }, have, 40, true)).toBe("skip");
  });

  it("is careful with odd values", () => {
    expect(noticeAction({ type: "sync", revision: 50, vaults: { A: "6" } }, have, 40, true)).toBe("sync");
    // No vault numbers (older server): the revision decides.
    expect(noticeAction({ type: "sync", revision: 50 }, have, 40, true)).toBe("sync");
    expect(noticeAction({ type: "sync", revision: 30 }, have, 40, true)).toBe("skip");
    expect(noticeAction({ type: "sync" }, have, 40, true)).toBe("skip");
  });

  it("keeps the revision rule without delta sync", () => {
    expect(noticeAction({ type: "sync", revision: 41, vaults: { A: 1 } }, have, 40, false)).toBe("sync");
    expect(noticeAction({ type: "sync", revision: 40, vaults: { A: 99 } }, have, 40, false)).toBe("skip");
  });
});

// --------------------------------------------------------- decrypted copies

describe("sameCiphertext", () => {
  it("holds while the encrypted item and its vault stay the same", () => {
    const a = row("x", "A");
    expect(sameCiphertext(a, a)).toBe(true);
    expect(sameCiphertext(a, { ...a, revision: 2, deleted_at: 99 })).toBe(true);
    expect(sameCiphertext(a, { ...a, data: "other" })).toBe(false);
    expect(sameCiphertext(a, { ...a, item_key: "other" })).toBe(false);
    expect(sameCiphertext(a, { ...a, vault_id: "B" })).toBe(false);
  });
});
