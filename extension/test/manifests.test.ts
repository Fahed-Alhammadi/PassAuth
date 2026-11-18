// Vault manifests, the pure parts (background/manifests.ts) with the real core:
// - the `vaultManifest` section of testdata/vectors.json through the WASM build the extension bundles: every verdict,
//   and every kind of write (the manifest after it is the one the core then accepts for the rows after it);
// - the rows as the core counts them (data, a trash summary's hash, a kept newer copy's served hash);
// - what this browser remembers (never lowered, malformed entries left out, vaults that are gone kept);
// - starting a manifest, the old-trash selection by the server's clock, the query of a request without a body.

import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";
import { expect, test } from "vitest";
import {
  dueTrash,
  entryOf,
  MANIFEST_BUSY_TEXT,
  MANIFEST_HELD_TEXT,
  MANIFEST_REVIEW_TEXT,
  MANIFEST_WARNING_TEXT,
  type ManifestItem,
  manifestItem,
  manifestItems,
  manifestNotice,
  manifestReady,
  manifestSeqOf,
  manifestTextOf,
  mayStart,
  mergeManifestMemory,
  purgeBatch,
  readManifestMemory,
  readServed,
  rememberManifest,
  SERVED_HASH,
  storedManifestMemory,
  unresolved,
  verifyVault,
  withManifest,
  writeQuery,
} from "../src/background/manifests";
import * as core from "../src/wasm/passauth_core";
import { fromB64u } from "./helpers";

interface Check {
  status: string;
  version: number;
  live: number;
  trashed: number;
}
interface Vectors {
  accountId: string;
  sessionBytes: string;
  vaultId: string;
  keyEpoch: number;
  wrappedKey: string;
  version: number;
  terms: { id: string; trashed: boolean; dataSha256: string }[];
  items: Record<string, Record<string, unknown>[]>;
  sealed: Record<string, string>;
  checks: { manifestSeq: number; sealed: string | null; remembered: number | null; items: string; expected: Check }[];
  writes: { name: string; removed: unknown[]; added: unknown[]; after: unknown[]; expected: { seq: number; live: number; trashed: number } }[];
}

const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const V = (Object.values(files)[0] as { vaultManifest: Vectors }).vaultManifest;
const key = () => core.accountFromSessionBytes(V.accountId, fromB64u(V.sessionBytes)).openVaultKey(V.vaultId, V.wrappedKey, "account", V.keyEpoch, false);

const vaultRow = (extra: Record<string, unknown> = {}): SyncVaultRow =>
  ({ id: V.vaultId, meta: "m", role: "owner", wrapped_key: V.wrappedKey, key_kind: "account", key_epoch: V.keyEpoch, seq: 7, ...extra }) as SyncVaultRow;
const itemRow = (id: string, extra: Record<string, unknown> = {}): SyncItemRow =>
  ({ id, vault_id: V.vaultId, item_key: "k", data: `data-${id}`, revision: 1, deleted_at: null, created_at: 0, updated_at: 0, ...extra }) as SyncItemRow;

test("vaultManifest vectors: every verdict, through the core the extension bundles", () => {
  expect(V, "testdata/vectors.json vaultManifest").toBeDefined();
  expect(V.checks.length).toBeGreaterThan(20);
  const k = key();
  for (const c of V.checks) {
    const sealed = c.sealed === null ? null : V.sealed[c.sealed];
    const got = k.manifestVerify(V.vaultId, V.keyEpoch, c.manifestSeq, sealed, c.remembered, V.items[c.items]) as Check;
    expect(got, JSON.stringify([c.manifestSeq, c.sealed, c.remembered, c.items])).toStrictEqual(c.expected);
    // The same through the extension's own wrapper, from a vault row and the rows as it maps them.
    const row = vaultRow({ manifest: sealed, manifest_seq: c.manifestSeq });
    const mapped = (V.items[c.items] as unknown as SyncItemRow[]).map(manifestItem);
    const mine = verifyVault(k, row, c.remembered ?? undefined, mapped);
    expect(mine, `wrapper: ${JSON.stringify([c.manifestSeq, c.sealed, c.remembered, c.items])}`).toStrictEqual({ status: c.expected.status, version: c.expected.version });
  }
  for (const status of ["none", "ok", "rollback", "mismatch", "incomplete"])
    expect(
      V.checks.some((c) => c.expected.status === status),
      status,
    ).toBe(true);
});

test("vaultManifest vectors: every kind of write gives the next manifest, which the core accepts for the rows after it", () => {
  const k = key();
  expect(V.writes.map((w) => w.name)).toStrictEqual(expect.arrayContaining(["create", "edit", "trash", "restore", "delete for good"]));
  for (const w of V.writes) {
    const next = entryOf(V.vaultId, k.manifestNext(V.vaultId, V.keyEpoch, V.version, V.sealed.current!, w.removed, w.added));
    expect(next.seq, w.name).toBe(w.expected.seq);
    expect(next.seq, w.name).toBe(V.version + 1);
    const after = k.manifestVerify(V.vaultId, V.keyEpoch, next.seq, next.sealed, V.version, w.after) as Check;
    expect(after, w.name).toStrictEqual({ status: "ok", version: next.seq, live: w.expected.live, trashed: w.expected.trashed });
    // The manifest from before no longer describes those rows (unless the write changed nothing).
    if (w.name !== "nothing") expect((k.manifestVerify(V.vaultId, V.keyEpoch, V.version, V.sealed.current, V.version, w.after) as Check).status, w.name).toBe("mismatch");
  }
  // A first manifest (or a new baseline) for exactly the rows held: the summary rows count by their hash.
  const started = k.manifestStart(V.vaultId, V.keyEpoch, 9, V.items.summary);
  expect((k.manifestVerify(V.vaultId, V.keyEpoch, 9, started, 3, V.items.full) as Check).status).toBe("ok");
  expect(() => k.manifestStart(V.vaultId, V.keyEpoch, 9, V.items.noHash)).toThrow();
  expect(core.manifestDataHash(V.items.full![0]!.data as string)).toBe(V.terms[0]!.dataSha256);
});

test("anything the core can't judge is a mismatch: rows it refuses (an id twice), a key that throws, an answer that isn't a verdict", () => {
  const k = key();
  const row = vaultRow({ manifest: V.sealed.current, manifest_seq: V.version });
  const rows = (V.items.full as unknown as SyncItemRow[]).map(manifestItem);
  expect(verifyVault(k, row, undefined, [...rows, rows[0]!])).toStrictEqual({ status: "mismatch", version: 0 });
  expect(verifyVault({ manifestVerify: () => ({ status: "fine" }) }, row, undefined, rows)).toStrictEqual({ status: "mismatch", version: 0 });
  expect(verifyVault({ manifestVerify: () => null }, row, undefined, rows)).toStrictEqual({ status: "mismatch", version: 0 });
  // A manifest that isn't text, or a version that isn't one: read as none, so a remembered version says rollback.
  expect(verifyVault(k, vaultRow({ manifest: 7, manifest_seq: V.version }), undefined, rows).status).toBe("mismatch");
  expect(verifyVault(k, vaultRow({ manifest: V.sealed.current, manifest_seq: "3" }), 3, rows).status).toBe("rollback");
  expect(verifyVault(k, vaultRow({ manifest: V.sealed.current, manifest_seq: "3" }), undefined, rows).status).toBe("none");
});

test("vault rows: the manifest fields as read; item rows: data, a summary's hash, a kept copy's served hash", () => {
  expect(manifestSeqOf(vaultRow())).toBe(0);
  expect(manifestSeqOf(vaultRow({ manifest_seq: 4 }))).toBe(4);
  for (const bad of [-1, 1.5, "4", null, Number.MAX_SAFE_INTEGER + 2]) expect(manifestSeqOf(vaultRow({ manifest_seq: bad }))).toBe(0);
  expect(manifestTextOf(vaultRow({ manifest: "abc" }))).toBe("abc");
  for (const bad of [null, "", 3, {}]) expect(manifestTextOf(vaultRow({ manifest: bad }))).toBe(null);
  expect(manifestReady(vaultRow({ manifest_ok: true }))).toBe(true);
  for (const bad of [undefined, false, 1, "true"]) expect(manifestReady(vaultRow({ manifest_ok: bad }))).toBe(false);

  expect(manifestItem(itemRow("a"))).toStrictEqual({ id: "a", deleted_at: null, data: "data-a" });
  expect(manifestItem(itemRow("a", { deleted_at: 5 }))).toStrictEqual({ id: "a", deleted_at: 5, data: "data-a" });
  // A trash summary: no data, the server's hash.
  expect(manifestItem(itemRow("a", { deleted_at: 5, data: undefined, item_key: undefined, data_sha256: "h" }))).toStrictEqual({ id: "a", deleted_at: 5, data_sha256: "h" });
  // One from before the server sent hashes: neither (the core says "incomplete").
  expect(manifestItem(itemRow("a", { deleted_at: 5, data: undefined }))).toStrictEqual({ id: "a", deleted_at: 5 });
  // A newer copy this browser kept instead of the server's older one: the server's data counts, by its hash.
  expect(manifestItem(itemRow("a", { [SERVED_HASH]: "served" }))).toStrictEqual({ id: "a", deleted_at: null, data_sha256: "served" });

  const snap = { items: new Map([itemRow("a"), itemRow("b", { vault_id: "other" }), itemRow("c", { deleted_at: 1 })].map((r) => [r.id, r])) };
  const by = manifestItems(snap);
  expect(by.get(V.vaultId)?.map((i) => i.id)).toStrictEqual(["a", "c"]);
  expect(by.get("other")?.map((i) => i.id)).toStrictEqual(["b"]);
});

test("memory: the highest version seen per vault, never lowered; malformed entries left out; vaults that are gone stay", () => {
  const m = readManifestMemory({ manifests: { a: 3, b: 0, c: -1, d: 1.5, e: "2", f: 9 } });
  expect([...m]).toStrictEqual([
    ["a", 3],
    ["f", 9],
  ]);
  rememberManifest(m, "a", 2);
  expect(m.get("a"), "never lowered").toBe(3);
  rememberManifest(m, "a", 4);
  rememberManifest(m, "new", 1);
  for (const bad of [0, -3, 1.5, Number.NaN]) rememberManifest(m, "bad", bad);
  expect(storedManifestMemory(m)).toStrictEqual({ manifests: { a: 4, f: 9, new: 1 } });
  expect(storedManifestMemory(new Map())).toStrictEqual({});
  for (const none of [null, undefined, {}, { manifests: [] }, { manifests: "x" }]) expect(readManifestMemory(none as never).size).toBe(0);
  // Two writers: each vault's higher version.
  expect(
    [
      ...mergeManifestMemory(
        new Map([
          ["a", 2],
          ["b", 5],
        ]),
        new Map([
          ["a", 3],
          ["c", 1],
        ]),
      ),
    ].sort(),
  ).toStrictEqual([
    ["a", 3],
    ["b", 5],
    ["c", 1],
  ]);
});

test("starting a vault's first manifest: only when the server keeps them and says every app can, with write access, nothing seen before and every row counted", () => {
  const features = new Set(["vault_manifest"]);
  const items: ManifestItem[] = [
    { id: "a", deleted_at: null, data: "x" },
    { id: "b", deleted_at: 3, data_sha256: "h" },
  ];
  const ok = { features, row: vaultRow({ manifest_seq: 0, manifest: null, manifest_ok: true }), role: "write", status: "none" as const, remembered: undefined, items };
  expect(mayStart(ok)).toBe(true);
  expect(mayStart({ ...ok, role: "owner" })).toBe(true);
  expect(mayStart({ ...ok, role: "admin" })).toBe(true);
  expect(mayStart({ ...ok, role: "read" }), "readers never write").toBe(false);
  expect(mayStart({ ...ok, role: "something" })).toBe(false);
  expect(mayStart({ ...ok, features: new Set() }), "a server without the feature").toBe(false);
  expect(mayStart({ ...ok, row: vaultRow({ manifest_seq: 0, manifest_ok: false }) }), "some member's app is too old").toBe(false);
  expect(mayStart({ ...ok, row: vaultRow({ manifest_seq: 0 }) }), "no gate named").toBe(false);
  expect(mayStart({ ...ok, row: vaultRow({ manifest_seq: 2, manifest: "m", manifest_ok: true }) }), "it has one").toBe(false);
  expect(mayStart({ ...ok, row: vaultRow({ manifest_seq: 0, manifest_ok: true, seq: undefined }) }), "no vault number to pin it to").toBe(false);
  expect(mayStart({ ...ok, remembered: 4 }), "one was seen here: its absence is a rollback, never a fresh start").toBe(false);
  for (const status of ["ok", "rollback", "mismatch", "incomplete", undefined] as const) expect(mayStart({ ...ok, status }), String(status)).toBe(false);
  expect(mayStart({ ...ok, items: [...items, { id: "c", deleted_at: 3 }] }), "a row with neither data nor hash").toBe(false);
  expect(mayStart({ ...ok, items: [] }), "an empty vault").toBe(true);
});

test("old trash: what the server's own clock and trash setting say is due; nothing when it keeps trash forever or names no clock", () => {
  const day = 86400;
  const now = 1_800_000_000;
  const rows = [
    itemRow("live"),
    itemRow("fresh", { deleted_at: now - 29 * day }),
    itemRow("edge", { deleted_at: now - 30 * day }),
    itemRow("due", { deleted_at: now - 30 * day - 1 }),
    itemRow("old", { deleted_at: 5, data: undefined, data_sha256: "h" }),
    itemRow("elsewhere", { deleted_at: 5, vault_id: "other" }),
    itemRow("odd", { deleted_at: "long ago" }),
  ];
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: 30 }).map((r) => r.id)).toStrictEqual(["due", "old"]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: 0 })).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: null })).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: null, trashDays: 30 })).toStrictEqual([]);
  // This browser's own clock never decides.
  expect(dueTrash(rows, V.vaultId, { serverTime: 10, trashDays: 30 })).toStrictEqual([]);
  expect(readServed({ server_time: now, trash_days: 30 })).toStrictEqual({ serverTime: now, trashDays: 30 });
  expect(readServed({ server_time: "now", trash_days: -1 })).toStrictEqual({ serverTime: null, trashDays: null });
  expect(readServed(null)).toStrictEqual({ serverTime: null, trashDays: null });
  expect(purgeBatch({ max_import_items: 40 })).toBe(40);
  for (const none of [null, {}, { max_import_items: 0 }, { max_import_items: "9" }]) expect(purgeBatch(none)).toBe(250);
});

test("what a write sends and what it leaves in the copy: body entries, the query of a request without a body, the row's manifest", () => {
  expect(entryOf("v", { seq: 4, sealed: "s" })).toStrictEqual({ vault_id: "v", seq: 4, sealed: "s" });
  for (const bad of [null, {}, { seq: 0, sealed: "s" }, { seq: 4, sealed: "" }, { seq: "4", sealed: "s" }]) expect(() => entryOf("v", bad)).toThrow();
  expect(writeQuery(undefined, null), "a vault without a manifest: the request as it always was").toBe("");
  expect(writeQuery(12, { vault_id: "v", seq: 4, sealed: "Ab-_9" })).toBe("?revision=12&manifest_seq=4&manifest=Ab-_9");
  expect(writeQuery(undefined, { vault_id: "v", seq: 4, sealed: "a b" })).toBe("?manifest_seq=4&manifest=a%20b");

  const snap: Snapshot = { revision: 1, cursor: "c", user: {} as never, bundle: {} as never, vaults: [vaultRow(), vaultRow({ id: "other" })], items: new Map(), invitations: [], own: { other: 2 } };
  const next = withManifest(snap, { vault_id: V.vaultId, seq: 4, sealed: "s" }, 8);
  expect([manifestSeqOf(next.vaults[0]!), manifestTextOf(next.vaults[0]!), manifestSeqOf(next.vaults[1]!)]).toStrictEqual([4, "s", 0]);
  expect(next.own).toStrictEqual({ other: 2, [V.vaultId]: 8 });
  expect(withManifest(snap, { vault_id: V.vaultId, seq: 4, sealed: "s" }).own, "with an item write the vault number comes from that write").toStrictEqual({ other: 2 });
  expect(manifestSeqOf(snap.vaults[0]!), "the snapshot given isn't changed").toBe(0);
});

test("the warning: the contract's words, for rollback and mismatch alike, naming the vaults; nothing for the other verdicts", () => {
  expect(MANIFEST_WARNING_TEXT).toBe("Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.");
  expect(MANIFEST_REVIEW_TEXT).toBe("Open the web vault or the desktop app to review this vault.");
  expect(MANIFEST_HELD_TEXT).toBe("This vault can't be changed until its warning is resolved.");
  expect(MANIFEST_BUSY_TEXT).toBe("This vault changed on another device. Try again.");
  expect(["rollback", "mismatch"].map((s) => unresolved(s as never))).toStrictEqual([true, true]);
  expect(["none", "ok", "incomplete", undefined].map((s) => unresolved(s as never))).toStrictEqual([false, false, false, false]);
  const vaults = [
    { id: "b", name: "Team" },
    { id: "a", name: "Personal" },
    { id: "c", name: "Fine" },
  ];
  expect(manifestNotice(vaults, new Map([["c", "ok"]]))).toBe(null);
  const n = manifestNotice(
    vaults,
    new Map([
      ["a", "mismatch"],
      ["b", "rollback"],
      ["c", "ok"],
    ]),
  );
  expect(n).toStrictEqual({ text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [vaults[0], vaults[1]], key: '["a","b"]' });
});
