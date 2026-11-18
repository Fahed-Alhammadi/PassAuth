/**
 * Vault manifests, the rules without network (`manifest.ts`, with the real core): the shared golden vectors, every
 * verdict, the entries writes carry, device memory, when a first manifest starts, a baseline's version and the trash
 * that is due.
 */
import { beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/passauth_core";
import { ApiError } from "./api";
import { afterWrite, applyOwnManifest, applyOwnWrite, knownSeq, mergeSync, type Snapshot } from "./delta";
import {
  MANIFESTS_PREFIX,
  ManifestMemory,
  baselineSeq,
  checkApplies,
  dueTrash,
  manifestQuery,
  manifestRaced,
  manifestRow,
  manifestSeq,
  manifestsKey,
  mayPurge,
  mayStart,
  nextEntry,
  readManifestVersions,
  startSealed,
  unresolved,
  verifyVault,
  withQuery,
} from "./manifest";
import { isTrustMemoryKey, type KeyValueStore } from "./signing";
import { allVectors, loadCore, unb64 } from "./test-core";
import { isSyncVaultRow, type SyncItemRow, type SyncResponse, type SyncVaultRow } from "./types";

interface Vectors {
  accountId: string;
  sessionBytes: string;
  vaultId: string;
  keyEpoch: number;
  wrappedKey: string;
  version: number;
  terms: { id: string; trashed: boolean; dataSha256: string }[];
  items: Record<string, SyncItemRow[]>;
  sealed: Record<string, string>;
  checks: { manifestSeq: number; sealed: string | null; remembered: number | null; items: string; expected: { status: string; version: number; live: number; trashed: number } }[];
  writes: { name: string; removed: unknown[]; added: unknown[]; after: SyncItemRow[]; expected: { seq: number; live: number; trashed: number } }[];
}

let v: Vectors;
let key: core.VaultKey;
const row = (over: Partial<SyncVaultRow> = {}): SyncVaultRow => ({
  id: v.vaultId,
  meta: "m",
  role: "owner",
  wrapped_key: v.wrappedKey,
  key_kind: "account",
  key_epoch: v.keyEpoch,
  seq: 9,
  manifest: v.sealed.current,
  manifest_seq: v.version,
  manifest_ok: true,
  ...over,
});

beforeAll(async () => {
  await loadCore();
  v = (await allVectors()).vaultManifest as Vectors;
  const account = core.accountFromSessionBytes(v.accountId, unb64(v.sessionBytes));
  key = account.openVaultKey(v.vaultId, v.wrappedKey, "account", v.keyEpoch, false);
});

const mapStore = () => {
  const m = new Map<string, string>();
  const store: KeyValueStore = { get: (k) => m.get(k) ?? null, set: (k, val) => void (val === null ? m.delete(k) : m.set(k, val)) };
  return { m, store };
};

describe("golden vectors (vaultManifest)", () => {
  it("every check gives the expected verdict, counts and version to remember", () => {
    expect(v.checks.length).toBeGreaterThan(5);
    for (const c of v.checks) {
      const got = key.manifestVerify(v.vaultId, v.keyEpoch, c.manifestSeq, c.sealed ? v.sealed[c.sealed] : null, c.remembered, v.items[c.items]);
      expect(got, JSON.stringify(c)).toEqual(c.expected);
    }
  });

  it("every write gives the next version, and the vault after it checks out", () => {
    expect(v.writes.length).toBeGreaterThan(4);
    for (const w of v.writes) {
      const next = key.manifestNext(v.vaultId, v.keyEpoch, v.version, v.sealed.current, w.removed, w.added) as { seq: number; sealed: string };
      expect(next.seq, w.name).toBe(w.expected.seq);
      const check = key.manifestVerify(v.vaultId, v.keyEpoch, next.seq, next.sealed, v.version, w.after);
      expect(check, w.name).toEqual({ status: "ok", version: w.expected.seq, live: w.expected.live, trashed: w.expected.trashed });
    }
  });

  it("the data hash is the one the vectors list", () => {
    const full = v.items.full;
    for (const t of v.terms) {
      const item = full.find((i) => i.id === t.id);
      if (item?.data) expect(core.manifestDataHash(item.data)).toBe(t.dataSha256);
    }
  });
});

describe("verifyVault", () => {
  it("ok: the version to remember is the row's, never below what was remembered", () => {
    expect(verifyVault(key, row(), undefined, v.items.full)).toEqual({ status: "ok", version: v.version });
    expect(verifyVault(key, row(), v.version, v.items.full)).toEqual({ status: "ok", version: v.version });
    expect(verifyVault(key, row(), 1, v.items.full)).toEqual({ status: "ok", version: v.version });
  });

  it("rollback: a lower version than remembered, or no manifest after one was seen; nothing new is remembered", () => {
    expect(verifyVault(key, row(), v.version + 1, v.items.full)).toEqual({ status: "rollback", version: v.version + 1 });
    expect(verifyVault(key, row({ manifest: null, manifest_seq: 0 }), 2, v.items.full)).toEqual({ status: "rollback", version: 2 });
  });

  it("none: no manifest and none seen", () => {
    expect(verifyVault(key, row({ manifest: null, manifest_seq: 0 }), undefined, v.items.full)).toEqual({ status: "none", version: 0 });
    expect(verifyVault(key, row({ manifest: undefined, manifest_seq: undefined }), undefined, [])).toEqual({ status: "none", version: 0 });
  });

  it("mismatch: an item changed, missing, added, or moved in or out of the trash", () => {
    const full = v.items.full;
    const older = full.map((r, i) => (i === 0 ? { ...r, data: `${r.data}x` } : r));
    const missing = full.slice(1);
    const extra = [...full, { ...full[0], id: "00000000-0000-4000-8000-0000000001ff" }];
    const restored = full.map((r) => ({ ...r, deleted_at: null }));
    for (const rows of [older, missing, extra, restored]) expect(verifyVault(key, row(), undefined, rows)).toEqual({ status: "mismatch", version: 0 });
    // What was remembered stays as it was.
    expect(verifyVault(key, row(), v.version, missing)).toEqual({ status: "mismatch", version: v.version });
  });

  it("mismatch: a manifest that doesn't open for this vault, epoch and version, or none where the row names a version", () => {
    expect(verifyVault(key, row({ manifest: v.sealed.otherVersion }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest: v.sealed.otherEpoch }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row({ key_epoch: v.keyEpoch + 1 }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest: null }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest: "not sealed" }), undefined, v.items.full).status).toBe("mismatch");
  });

  it("mismatch for anything the core refuses: an id listed twice, a version that isn't a whole number", () => {
    expect(verifyVault(key, row(), undefined, [...v.items.full, v.items.full[0]]).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest_seq: -1 }), 5, v.items.full)).toEqual({ status: "mismatch", version: 5 });
    expect(verifyVault(key, row({ manifest_seq: 1.5 }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest_seq: "3" as unknown as number }), undefined, v.items.full).status).toBe("mismatch");
  });

  it("incomplete: a row with neither its data nor its hash; a row with only the hash counts as the item", () => {
    const [first, ...rest] = v.items.full;
    const bare = { id: first.id, deleted_at: first.deleted_at } as unknown as SyncItemRow;
    expect(verifyVault(key, row(), undefined, [bare, ...rest]).status).toBe("incomplete");
    const hashed = { ...bare, data_sha256: core.manifestDataHash(first.data) } as unknown as SyncItemRow;
    expect(verifyVault(key, row(), undefined, [hashed, ...rest]).status).toBe("ok");
    expect(manifestRow(hashed)).toEqual({ id: first.id, deleted_at: null, data_sha256: hashed.data_sha256 });
  });

  it("only rollback, mismatch and incomplete hold a vault's writes back", () => {
    expect(["none", "ok", "rollback", "mismatch", "incomplete", undefined].map((s) => unresolved(s as never))).toEqual([false, false, true, true, true, false]);
  });
});

describe("which vaults are checked", () => {
  it("with the feature, or a manifest on the row, or a version remembered: a server can't switch the check off by not listing it", () => {
    const none = { manifest_seq: 0, manifest: null };
    expect(checkApplies(true, none, undefined)).toBe(true);
    expect(checkApplies(false, none, undefined)).toBe(false);
    expect(checkApplies(false, { manifest_seq: 2, manifest: "x" }, undefined)).toBe(true);
    expect(checkApplies(false, { manifest_seq: 0, manifest: "x" }, undefined)).toBe(true);
    expect(checkApplies(false, none, 4)).toBe(true);
    // And the remembered version then reads as a rollback.
    expect(verifyVault(key, row(none), 4, v.items.full).status).toBe("rollback");
  });
});

describe("the entries writes carry", () => {
  const full = () => v.items.full;
  const after = (rows: SyncItemRow[], entry: { seq: number; sealed: string } | null) => verifyVault(key, row({ manifest: entry!.sealed, manifest_seq: entry!.seq }), v.version, rows);

  it("nothing for a vault without a manifest", () => {
    expect(nextEntry(key, row({ manifest: null, manifest_seq: 0 }), [], [{ id: "x", deleted_at: null, data: "d" }])).toBeNull();
    expect(nextEntry(key, row({ manifest: undefined, manifest_seq: undefined }), [], [])).toBeNull();
    expect(manifestQuery(null)).toEqual([]);
    expect(withQuery("/items/x", [])).toBe("/items/x");
  });

  it("create, edit, trash, restore and delete for good: one version up, and the vault after the write checks out", () => {
    const [a, b, c] = full();
    const created: SyncItemRow = { ...a, id: "00000000-0000-4000-8000-0000000001aa", data: "new-data" };
    const e1 = nextEntry(key, row(), [], [manifestRow(created)]);
    expect(e1).toMatchObject({ vault_id: v.vaultId, seq: v.version + 1 });
    expect(after([...full(), created], e1).status).toBe("ok");

    const edited = { ...a, data: "edited-data" };
    expect(after([edited, b, c], nextEntry(key, row(), [manifestRow(a)], [manifestRow(edited)])).status).toBe("ok");

    const trashed = { ...a, deleted_at: 77 };
    expect(after([trashed, b, c], nextEntry(key, row(), [manifestRow(a)], [manifestRow(trashed)])).status).toBe("ok");

    const wasTrashed = full().find((r) => r.deleted_at !== null)!;
    const others = full().filter((r) => r !== wasTrashed);
    const restored = { ...wasTrashed, deleted_at: null };
    expect(after([...others, restored], nextEntry(key, row(), [manifestRow(wasTrashed)], [manifestRow(restored)])).status).toBe("ok");
    expect(after(others, nextEntry(key, row(), [manifestRow(wasTrashed)], [])).status).toBe("ok");
    // A wrong "before" gives a manifest the vault doesn't match.
    expect(after([edited, b, c], nextEntry(key, row(), [manifestRow(b)], [manifestRow(edited)])).status).toBe("mismatch");
  });

  it("the query of a write without a body, and a whole manifest for a new key", () => {
    const entry = nextEntry(key, row(), [], [{ id: "00000000-0000-4000-8000-0000000001ab", deleted_at: null, data: "d" }])!;
    expect(withQuery("/items/i", ["revision=4", ...manifestQuery(entry)])).toBe(`/items/i?revision=4&manifest_seq=${entry.seq}&manifest=${entry.sealed}`);
    expect(entry.sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    const sealed = startSealed(key, v.vaultId, v.keyEpoch + 1, 9, full().map(manifestRow));
    expect(verifyVault(key, row({ manifest: sealed, manifest_seq: 9, key_epoch: v.keyEpoch + 1 }), 3, full())).toEqual({ status: "ok", version: 9 });
    // Sealed for another epoch or version it doesn't open.
    expect(verifyVault(key, row({ manifest: sealed, manifest_seq: 9 }), 3, full()).status).toBe("mismatch");
    expect(verifyVault(key, row({ manifest: sealed, manifest_seq: 10, key_epoch: v.keyEpoch + 1 }), 3, full()).status).toBe("mismatch");
  });

  it("a row without a readable manifest or key epoch is never built on", () => {
    expect(() => nextEntry(key, row({ manifest: null }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row({ key_epoch: undefined }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row({ manifest: v.sealed.otherVersion }), [], [])).toThrow();
  });

  it("manifest_conflict and manifest_required (a 400) both mean: sync, check, compute again", () => {
    expect(manifestRaced(new ApiError(409, "manifest_conflict", "x"))).toBe(true);
    expect(manifestRaced(new ApiError(400, "manifest_required", "Update PassAuth to change this vault."))).toBe(true);
    expect(manifestRaced(new ApiError(409, "manifest_not_ready", "x"))).toBe(false);
    expect(manifestRaced(new ApiError(409, "revision_conflict", "x"))).toBe(false);
    expect(manifestRaced(new Error("manifest_conflict"))).toBe(false);
  });
});

describe("device memory", () => {
  const scope = "https://vault.example.test|acct";

  it("is only ever raised, per vault, and survives a reload", () => {
    const { m, store } = mapStore();
    const memory = new ManifestMemory(store, scope);
    expect(memory.get("v1")).toBeUndefined();
    memory.raise("v1", 3);
    memory.raise("v1", 2);
    memory.raise("v2", 1);
    memory.raise("v3", 0);
    memory.raise("v3", 1.5);
    memory.flush();
    expect(JSON.parse(m.get(manifestsKey(scope))!)).toEqual({ v1: 3, v2: 1 });
    const again = new ManifestMemory(store, scope);
    expect(again.get("v1")).toBe(3);
    expect(again.get("v3")).toBeUndefined();
  });

  it("merges with another tab's writes: the higher version wins, nothing is dropped", () => {
    const { m, store } = mapStore();
    const one = new ManifestMemory(store, scope);
    const two = new ManifestMemory(store, scope);
    one.raise("v1", 5);
    one.raise("gone", 2);
    one.flush();
    two.raise("v1", 4);
    two.raise("v2", 7);
    two.flush();
    expect(JSON.parse(m.get(manifestsKey(scope))!)).toEqual({ v1: 5, v2: 7, gone: 2 });
    expect(two.get("v1")).toBe(5);
    one.refresh();
    expect(one.get("v2")).toBe(7);
  });

  it("writes nothing when nothing was raised, reads garbage as nothing, and is kept with the other device memory", () => {
    const { m, store } = mapStore();
    new ManifestMemory(store, scope).flush();
    expect(m.size).toBe(0);
    m.set(manifestsKey(scope), "{not json");
    expect(readManifestVersions(store, scope).size).toBe(0);
    m.set(manifestsKey(scope), JSON.stringify({ a: 2, b: "3", c: -1, d: 0, e: 1.5 }));
    expect([...readManifestVersions(store, scope)]).toEqual([["a", 2]]);
    expect(isTrustMemoryKey(manifestsKey(scope))).toBe(true);
    expect(manifestsKey(scope).startsWith(MANIFESTS_PREFIX)).toBe(true);
  });
});

describe("starting a first manifest", () => {
  const none = (over: Partial<SyncVaultRow> = {}) => row({ manifest: null, manifest_seq: 0, manifest_ok: true, ...over });

  it("only with the feature, the server's go-ahead, write access, no manifest and none ever seen", () => {
    expect(mayStart(true, none(), "none", undefined)).toBe(true);
    for (const role of ["write", "admin", "owner"] as const) expect(mayStart(true, none({ role }), "none", undefined)).toBe(true);
    expect(mayStart(false, none(), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: false }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: undefined }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: 1 as unknown as boolean }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ role: "read" }), "none", undefined)).toBe(false);
    expect(mayStart(true, none(), "none", 2)).toBe(false);
    expect(mayStart(true, none(), "rollback", 2)).toBe(false);
    expect(mayStart(true, row(), "ok", undefined)).toBe(false);
    expect(mayStart(true, none({ seq: undefined }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ key_epoch: undefined }), "none", undefined)).toBe(false);
  });
});

describe("a new baseline", () => {
  it("is one above the server's version and the remembered one, whichever is higher", () => {
    expect(baselineSeq({ manifest_seq: 3 }, undefined)).toBe(4);
    expect(baselineSeq({ manifest_seq: 3 }, 9)).toBe(10);
    expect(baselineSeq({ manifest_seq: 9 }, 3)).toBe(10);
    expect(baselineSeq({ manifest_seq: 0 }, 5)).toBe(6);
    expect(baselineSeq({}, undefined)).toBe(1);
    expect(manifestSeq({ manifest_seq: -2 })).toBe(0);
  });
});

describe("old trash", () => {
  const item = (id: string, deleted_at: number | null): SyncItemRow => ({ id, vault_id: "v", item_key: "k", data: "d", revision: 1, deleted_at, created_at: 1, updated_at: 1 });
  const rows = [item("live", null), item("old", 1000), item("edge", 1000 + 86400), item("new", 5000 + 86400)];

  it("is what has been in the trash longer than the server's retention, by the server's clock", () => {
    const serverTime = 1000 + 2 * 86400;
    expect(dueTrash(rows, serverTime, 1).map((r) => r.id)).toEqual(["old"]);
    expect(dueTrash(rows, serverTime + 1, 1).map((r) => r.id)).toEqual(["old", "edge"]);
    expect(dueTrash(rows, serverTime, 30)).toEqual([]);
  });

  it("is nothing when the server keeps the trash forever or didn't say", () => {
    expect(dueTrash(rows, 9e9, 0)).toEqual([]);
    expect(dueTrash(rows, 9e9, undefined)).toEqual([]);
    expect(dueTrash(rows, undefined, 30)).toEqual([]);
    expect(dueTrash(rows, 9e9, -1)).toEqual([]);
  });

  it("is deleted only in a vault that checked out, has a manifest and can be written", () => {
    expect(mayPurge(row(), "ok")).toBe(true);
    expect(mayPurge(row({ role: "read" }), "ok")).toBe(false);
    expect(mayPurge(row(), "mismatch")).toBe(false);
    expect(mayPurge(row(), "rollback")).toBe(false);
    expect(mayPurge(row({ manifest: null, manifest_seq: 0 }), "none")).toBe(false);
  });
});

describe("delta sync carries the manifest", () => {
  const user = { id: "u", email: "u@example.com", name: "U", email_verified: true };
  const item = (id: string, data = "d"): SyncItemRow => ({ id, vault_id: "v1", item_key: "k", data, revision: 1, deleted_at: null, created_at: 1, updated_at: 1 });
  const vault = (over: Partial<SyncVaultRow> = {}): SyncVaultRow => ({ id: "v1", meta: "m", role: "owner", wrapped_key: "w", key_kind: "account", key_epoch: 0, seq: 4, manifest: "aaa", manifest_seq: 2, manifest_ok: true, ...over });
  const answer = (over: Partial<SyncResponse> = {}): SyncResponse => ({ revision: 1, user, bundle: { account_id: "u", kdf: {}, secret_key_enabled: false }, vaults: [vault()], items: [item("a")], cursor: "c1", ...over });
  const snap = (over: Partial<SyncResponse> = {}): Snapshot => mergeSync(null, answer(over))!.snapshot;

  it("vault rows keep manifest, manifest_seq and manifest_ok; the answer's clock and retention are kept", () => {
    const s = snap({ server_time: 1234, trash_days: 30 });
    expect(s.vaults[0]).toMatchObject({ manifest: "aaa", manifest_seq: 2, manifest_ok: true });
    expect(s.serverTime).toBe(1234);
    expect(s.trashDays).toBe(30);
    const d = mergeSync(s, answer({ delta: true, items: [], vaults: [vault({ manifest: "bbb", manifest_seq: 3, seq: 5 })], cursor: "c2", server_time: 2000, trash_days: 0 }))!.snapshot;
    expect(d.vaults[0]).toMatchObject({ manifest: "bbb", manifest_seq: 3 });
    expect(d.serverTime).toBe(2000);
    expect(d.trashDays).toBe(0);
    // An older server sends neither.
    expect(snap().serverTime).toBeUndefined();
    expect(snap({ server_time: -5 as number, trash_days: "30" as unknown as number }).serverTime).toBeUndefined();
  });

  it("a vault row whose manifest fields have the wrong type is refused", () => {
    expect(isSyncVaultRow(vault())).toBe(true);
    expect(isSyncVaultRow(vault({ manifest: null, manifest_seq: 0 }))).toBe(true);
    expect(isSyncVaultRow({ ...vault(), manifest: undefined, manifest_seq: undefined })).toBe(true);
    expect(isSyncVaultRow(vault({ manifest: 5 as unknown as string }))).toBe(false);
    expect(isSyncVaultRow(vault({ manifest_seq: "2" as unknown as number }))).toBe(false);
  });

  it("an own write is shown without asking only when the answer's manifest version is the one sent", () => {
    // No manifest in play: as before.
    expect(afterWrite(4, 5, true)).toBe("apply");
    expect(afterWrite(4, 5, true, { sent: undefined, answered: undefined })).toBe("apply");
    expect(afterWrite(4, 5, true, { sent: undefined, answered: 0 })).toBe("apply");
    // Sent and answered with exactly that version.
    expect(afterWrite(4, 5, true, { sent: 3, answered: 3 })).toBe("apply");
    // Anything else is a sync: no version in the answer, another one, or a manifest this client didn't know of.
    expect(afterWrite(4, 5, true, { sent: 3, answered: undefined })).toBe("sync");
    expect(afterWrite(4, 5, true, { sent: 3, answered: 4 })).toBe("sync");
    expect(afterWrite(4, 5, true, { sent: 3, answered: "3" })).toBe("sync");
    expect(afterWrite(4, 5, true, { sent: undefined, answered: 2 })).toBe("sync");
    // A write a sync already brought needs nothing, whatever the manifest says.
    expect(afterWrite(5, 5, true, { sent: 3, answered: 9 })).toBe("none");
    expect(afterWrite(4, 6, true, { sent: 3, answered: 3 })).toBe("sync");
    expect(afterWrite(4, 5, false, { sent: 3, answered: 3 })).toBe("sync");
  });

  it("showing an own write puts its manifest on the vault row, and the next answer replaces it", () => {
    const s = snap();
    const shown = applyOwnWrite(s, { kind: "upsert", row: item("b"), vaultSeq: 5, manifest: { seq: 3, sealed: "bbb" } });
    expect(shown.vaults[0]).toMatchObject({ manifest: "bbb", manifest_seq: 3, seq: 4 });
    expect(knownSeq(shown, "v1")).toBe(5);
    expect(s.vaults[0]).toMatchObject({ manifest: "aaa", manifest_seq: 2 });
    // Without a manifest the row is untouched (a vault that has none).
    expect(applyOwnWrite(s, { kind: "remove", id: "a", vaultId: "v1", vaultSeq: 5 }).vaults).toBe(s.vaults);
    const removed = applyOwnWrite(shown, { kind: "remove", id: "a", vaultId: "v1", vaultSeq: 6, manifest: { seq: 4, sealed: "ccc" } });
    expect(removed.vaults[0]).toMatchObject({ manifest: "ccc", manifest_seq: 4 });
    expect([...removed.items.keys()]).toEqual(["b"]);
    const merged = mergeSync(removed, answer({ delta: true, items: [item("b")], deleted: [{ id: "a", vault_id: "v1" }], vaults: [vault({ manifest: "ccc", manifest_seq: 4, seq: 6 })], cursor: "c2" }))!;
    expect(merged.behind).toBe(false);
    expect(merged.snapshot.vaults[0]).toMatchObject({ manifest: "ccc", manifest_seq: 4, seq: 6 });
  });

  it("a manifest stored by itself (a first one, a baseline) moves only the vault row and its number", () => {
    const s = snap({ vaults: [vault({ manifest: null, manifest_seq: 0 }), vault({ id: "v2" })] });
    const next = applyOwnManifest(s, "v1", { seq: 1, sealed: "first" }, 5);
    expect(next.vaults[0]).toMatchObject({ manifest: "first", manifest_seq: 1 });
    expect(next.vaults[1]).toBe(s.vaults[1]);
    expect(next.items).toBe(s.items);
    expect(knownSeq(next, "v1")).toBe(5);
  });
});
