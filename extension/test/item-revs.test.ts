// Item rollback detection, the pure parts (background/item-revs.ts) and the `itemRev` section of testdata/vectors.json
// through the real core the extension bundles (`itemRevCheck`).

import { expect, test } from "vitest";
import { capRevMemory, emptyRevMemory, forgetRev, itemRevOf, noteServed, REV_MEMORY_CAP, readRevMemory, rollbackNotice, storedRevMemory } from "../src/background/item-revs";
import * as core from "../src/wasm/passauth_core";
import { fromB64u } from "./helpers";

interface ItemRevVectors {
  checks: { remembered: number | null; served: number; expected: string }[];
  limits: {
    accountId: string;
    sessionBytes: string;
    vaultId: string;
    keyEpoch: number;
    wrappedKey: string;
    top: number;
    items: { rev: string; reads: number; writes: number; encrypted: { id: string; vault_id: string; key: string; data: string } }[];
  };
}
const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const V = (Object.values(files)[0] as { itemRev: ItemRevVectors }).itemRev;

test("vectors: itemRevCheck through the WASM core", () => {
  expect(V.checks.map((c) => c.expected)).toEqual(expect.arrayContaining(["new", "newer", "same", "rollback"]));
  for (const c of V.checks) expect(core.itemRevCheck(c.remembered, c.served), JSON.stringify(c)).toBe(c.expected);
});

test("vectors: an item sealed with a counter near or beyond 2^53 still opens and can be saved again (nothing here breaks on it either)", () => {
  const L = V.limits;
  expect(L.items.length).toBeGreaterThan(5);
  const key = core.accountFromSessionBytes(L.accountId, fromB64u(L.sessionBytes)).openVaultKey(L.vaultId, L.wrappedKey, "account", L.keyEpoch, false);
  for (const c of L.items) {
    const item = key.decryptItem(c.encrypted) as { rev: number };
    expect(item.rev, `rev ${c.rev} reads`).toBe(c.reads);
    expect(Number.isSafeInteger(itemRevOf(item)), c.rev).toBe(true);
    expect(itemRevOf(item), c.rev).toBe(c.reads);
    const again = key.decryptItem(key.updateItem(c.encrypted, item)) as { rev: number };
    expect(again.rev, `rev ${c.rev} writes`).toBe(Math.min(c.writes, L.top));
    // The check and this browser's memory take such counters like any other.
    const m = emptyRevMemory();
    expect(noteServed(m, "x", itemRevOf(item), core.itemRevCheck(null, itemRevOf(item)), true, () => null)).toBe("show");
    expect(core.itemRevCheck(m.revs.get("x") ?? null, itemRevOf(again))).toMatch(/^(newer|same)$/);
    expect(readRevMemory(JSON.parse(JSON.stringify(storedRevMemory(m))))).toStrictEqual(m);
  }
});

test("noteServed: new/newer remembered, same accepted, rollback marked and never lowers the counter; the newer copy is kept", () => {
  const m = emptyRevMemory();
  expect(noteServed(m, "a", 3, "new", true, () => null)).toBe("show");
  expect(m.revs.get("a")).toBe(3);
  // Older, with a newer copy here: keep it.
  expect(noteServed(m, "a", 2, "rollback", true, () => 3)).toBe("keep");
  expect(m.revs.get("a")).toBe(3);
  expect(m.rolledBack.get("a")).toBe("kept");
  // Older, no copy (or one no newer than the server's): the server's is shown, marked "older".
  expect(noteServed(m, "b", 1, "rollback", true, () => null)).toBe("show");
  expect(noteServed(m, "c", 1, "rollback", true, () => 1)).toBe("show");
  expect(m.rolledBack.get("b")).toBe("older");
  expect(m.rolledBack.get("c")).toBe("older");
  // The kept copy read again from the offline copy (same counter, unchanged): still marked.
  expect(noteServed(m, "a", 3, "same", false, () => null)).toBe("show");
  expect(m.rolledBack.get("a")).toBe("kept");
  // The server sends the remembered version again (a changed row, same counter): the mark goes.
  noteServed(m, "a", 3, "same", true, () => null);
  expect(m.rolledBack.has("a")).toBe(false);
  // A newer one clears a mark too.
  noteServed(m, "b", 4, "newer", true, () => null);
  expect(m.rolledBack.has("b")).toBe(false);
  expect(m.revs.get("b")).toBe(4);
  // An unknown verdict is never taken as fine.
  noteServed(m, "d", 0, "???", true, () => null);
  expect(m.rolledBack.get("d")).toBe("older");
  expect(m.revs.has("d")).toBe(false);
});

test("stored form round trip, malformed entries left out, forgetting and the notice", () => {
  const m = emptyRevMemory();
  noteServed(m, "a", 3, "new", true, () => null);
  noteServed(m, "b", 1, "new", true, () => null);
  noteServed(m, "b", 0, "rollback", true, () => null);
  const stored = storedRevMemory(m);
  expect(stored).toStrictEqual({ itemRevs: { a: 3, b: 1 }, rolledBack: { b: "older" } });
  expect(readRevMemory(JSON.parse(JSON.stringify(stored)))).toStrictEqual(m);
  expect(storedRevMemory(emptyRevMemory())).toStrictEqual({});
  const bad = readRevMemory({ itemRevs: { x: -1, y: 1.5, z: "3", ok: 2 }, rolledBack: { x: "maybe", ok: "kept" } });
  expect([...bad.revs]).toStrictEqual([["ok", 2]]);
  expect([...bad.rolledBack]).toStrictEqual([["ok", "kept"]]);
  expect(readRevMemory({ itemRevs: [1, 2] as unknown as Record<string, number> }).revs.size).toBe(0);
  expect(rollbackNotice(m, new Set(["a", "b"]))?.text).toBe("Your server sent older versions of some items.");
  expect(rollbackNotice(m, new Set(["a"]))).toBe(null);
  // Forgotten only one by one, by whoever proved the item gone (vault.ts): never for an item merely missing.
  forgetRev(m, "b");
  expect(storedRevMemory(m)).toStrictEqual({ itemRevs: { a: 3 } });
  expect(itemRevOf({ rev: 7 })).toBe(7);
  expect(itemRevOf({ rev: "7" })).toBe(0);
  expect(itemRevOf({})).toBe(0);
  expect(itemRevOf(null)).toBe(0);
});

test("the cap: at most 20,000 counters; the least recently seen go first, items this browser no longer holds before ones it holds", () => {
  expect(REV_MEMORY_CAP).toBe(20_000);
  const m = emptyRevMemory();
  for (const id of ["gone1", "held1", "gone2", "held2", "held3"]) noteServed(m, id, 1, "new", true, () => null);
  m.rolledBack.set("gone1", "older");
  const held = new Set(["held1", "held2", "held3"]);
  capRevMemory(m, held, 5);
  expect(m.revs.size, "within the cap: nothing goes").toBe(5);
  capRevMemory(m, held, 4);
  expect([...m.revs.keys()]).toStrictEqual(["held1", "gone2", "held2", "held3"]);
  expect(m.rolledBack.has("gone1"), "its mark goes with it").toBe(false);
  // Seen again: moved to the newest end, so it outlives the others.
  noteServed(m, "held1", 1, "same", false, () => null);
  capRevMemory(m, held, 2);
  expect([...m.revs.keys()]).toStrictEqual(["held3", "held1"]);
  noteServed(m, "held3", 2, "newer", true, () => null);
  capRevMemory(m, held, 1);
  expect([...m.revs]).toStrictEqual([["held3", 2]]);
});
