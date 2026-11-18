import { beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/passauth_core";
import { RevMemory, checkRev, readRevs, revOf, revsKey } from "./item-revs";
import type { KeyValueStore } from "./signing";
import { allVectors, loadCore, signedVectors, vectorAccounts } from "./test-core";
import { emptyItem, type Item } from "./types";

const mapStore = () => {
  const m = new Map<string, string>();
  const store: KeyValueStore = { get: (k) => m.get(k) ?? null, set: (k, v) => void (v === null ? m.delete(k) : m.set(k, v)) };
  return { m, store };
};

beforeAll(loadCore);

describe("item edit counters", () => {
  it("checks like the shared vectors", async () => {
    const v = (await allVectors()).itemRev as { checks: { remembered: number | null; served: number; expected: string }[] };
    for (const c of v.checks) expect(checkRev(c.remembered ?? undefined, c.served), JSON.stringify(c)).toBe(c.expected);
  });

  it("the core counts up on encrypt, update and a move", async () => {
    const alice = vectorAccounts(await signedVectors()).get("alice")!.account;
    const nv = alice.newVaultKey("vault-a");
    const key = nv.takeKey();
    const item: Item = { ...emptyItem("login"), name: "Mail", created_at: 1, updated_at: 1 };
    const enc = key.encryptItem(item, "i", "vault-a");
    const first = key.decryptItem(enc) as Item;
    expect(first.rev).toBe(1);
    const updated = key.updateItem(enc, { ...first, name: "Mail 2" });
    expect((key.decryptItem(updated) as Item).rev).toBe(2);
    // An app that dropped the counter still counts up from the stored one.
    const { rev: _dropped, ...withoutRev } = first;
    const dropped = key.updateItem(updated, { ...withoutRev, name: "Mail 3" });
    expect((key.decryptItem(dropped) as Item).rev).toBe(3);
    key.free();
  });

  it("reads a counter: missing or malformed is 0", () => {
    expect(revOf({ rev: 4 })).toBe(4);
    expect(revOf({})).toBe(0);
    expect(revOf({ rev: -1 })).toBe(0);
    expect(revOf({ rev: 1.5 })).toBe(0);
    expect(revOf({ rev: "3" as unknown as number })).toBe(0);
    expect(revOf(null)).toBe(0);
  });

  it("remembers new and newer counters, never lowers one, and keeps them per scope", () => {
    const { store, m } = mapStore();
    const mem = new RevMemory(store, "s|a");
    expect(mem.check("x", 1)).toBe("new");
    expect(mem.check("x", 3)).toBe("newer");
    expect(mem.check("x", 3)).toBe("same");
    expect(mem.check("x", 2)).toBe("rollback");
    expect(mem.get("x")).toBe(3);
    mem.flush();
    expect(JSON.parse(m.get(revsKey("s|a"))!)).toEqual({ x: 3 });
    expect(readRevs(store, "s|b").size).toBe(0);
    // Loaded again (a new page): the rollback is still seen.
    expect(new RevMemory(store, "s|a").check("x", 1)).toBe("rollback");
  });

  it("forgets ids no longer served, and merges with what another tab wrote", () => {
    const { store, m } = mapStore();
    const a = new RevMemory(store, "s|a");
    a.check("x", 1);
    a.check("y", 1);
    a.flush();
    const b = new RevMemory(store, "s|a");
    b.check("x", 5);
    b.check("z", 2);
    b.flush();
    // Tab a drops y, raises nothing: x keeps tab b's 5, z comes in, y stays gone.
    a.prune(new Set(["x", "z"]));
    a.flush();
    expect(JSON.parse(m.get(revsKey("s|a"))!)).toEqual({ x: 5, z: 2 });
  });

  it("reads an unreadable store as nothing remembered", () => {
    const { store, m } = mapStore();
    m.set(revsKey("s|a"), "{not json");
    expect(readRevs(store, "s|a").size).toBe(0);
    m.set(revsKey("s|a"), JSON.stringify({ x: 2, y: "3", z: -1 }));
    expect([...readRevs(store, "s|a")]).toEqual([["x", 2]]);
  });

  it("a counter the core won't take is never remembered", () => {
    expect(checkRev(undefined, Number.MAX_SAFE_INTEGER * 4)).toBe("same");
    expect(core.itemRevCheck(null, 0)).toBe("new");
  });
});
