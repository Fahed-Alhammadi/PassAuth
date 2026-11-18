// Vault manifests, the pure parts (background/manifests.ts) with the real core:
// - the `vaultManifest` section of testdata/vectors.json through the WASM build the extension bundles: every verdict
//   (the chain included: links, `need_log`, logs, forks, key replacements, baselines), rows the core must refuse,
//   every kind of write and every kind of start;
// - the rows as the core counts them (data, a trash summary's hash, a kept newer copy's served hash, which is never
//   read from the row), the one "in the trash" predicate;
// - what this browser remembers (version + link; never lowered, a link never replaced at its version, old formats
//   and half entries are nothing);
// - the manifest log (paging, its cap), starting a manifest, the old-trash selection (bounded by what this browser
//   saw itself), the numbers of an answer, the query of a request without a body.

import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";
import { expect, test } from "vitest";
import {
  behindOwn,
  CLOCK_TOLERANCE,
  collectLog,
  dueTrash,
  entryOf,
  isLink,
  isTrashed,
  LOG_REQUESTS,
  MANIFEST_BUSY_TEXT,
  MANIFEST_HELD_TEXT,
  MANIFEST_REVIEW_TEXT,
  MANIFEST_WARNING_TEXT,
  type ManifestItem,
  type ManifestMemory,
  manifestItem,
  manifestItems,
  manifestNotice,
  manifestPrevOf,
  manifestReady,
  manifestSeqOf,
  manifestTextOf,
  mayStart,
  mergeManifestMemory,
  noteTrash,
  purgeBatch,
  type Remembered,
  readManifestMemory,
  readServed,
  readTrashSeen,
  rememberManifest,
  SERVED_HASH,
  sentEntry,
  storedManifestMemory,
  stripPrivate,
  unresolved,
  unsettled,
  validNumbers,
  verifyVault,
  withManifest,
  writeQuery,
} from "../src/background/manifests";
import * as core from "../src/wasm/passauth_core";
import { fromB64u } from "./helpers";

interface Check {
  status: string;
  version: number;
  link: string | null;
  live: number;
  trashed: number;
}
interface Row {
  manifest_seq: number;
  manifest_prev: string | null;
  manifest: string | null;
  link: string | null;
}
type KeyName = "main" | "rotated";
interface Vectors {
  accountId: string;
  sessionBytes: string;
  vaultId: string;
  keyEpoch: number;
  wrappedKey: string;
  rotated: { keyEpoch: number; wrappedKey: string };
  terms: { id: string; trashed: boolean; dataSha256: string }[];
  items: Record<string, Record<string, unknown>[]>;
  malformed: { deletedAt: unknown; items: unknown[] }[];
  manifests: Record<string, Row>;
  checks: { name: string; manifest: string; key: KeyName; keyEpoch: number; remembered: Remembered | null; log: unknown[] | null; items: string; expected: Check }[];
  writes: { name: string; removed: unknown[]; added: unknown[]; after: unknown[]; expected: { seq: number; prev: string; live: number; trashed: number } }[];
  starts: { name: string; key: KeyName; keyEpoch: number; version: number; prev: string | null; items: string; remembered: Remembered | null; expected: { seq: number; prev: string } }[];
}

const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const V = (Object.values(files)[0] as { vaultManifest: Vectors }).vaultManifest;
const account = () => core.accountFromSessionBytes(V.accountId, fromB64u(V.sessionBytes));
const keys = (): Record<KeyName, core.VaultKey> => ({
  main: account().openVaultKey(V.vaultId, V.wrappedKey, "account", V.keyEpoch, false),
  rotated: account().openVaultKey(V.vaultId, V.rotated.wrappedKey, "account", V.rotated.keyEpoch, false),
});
const key = () => keys().main;
const current = () => V.manifests.current as Required<Row> & { manifest: string; manifest_prev: string; link: string };

const vaultRow = (extra: Record<string, unknown> = {}): SyncVaultRow =>
  ({ id: V.vaultId, meta: "m", role: "owner", wrapped_key: V.wrappedKey, key_kind: "account", key_epoch: V.keyEpoch, seq: 7, ...extra }) as SyncVaultRow;
/** The vault row of a named manifest of the vectors. */
const rowOf = (name: string, keyEpoch = V.keyEpoch): SyncVaultRow => {
  const m = V.manifests[name]!;
  return vaultRow({ manifest: m.manifest, manifest_seq: m.manifest_seq, manifest_prev: m.manifest_prev, key_epoch: keyEpoch });
};
const itemRow = (id: string, extra: Record<string, unknown> = {}): SyncItemRow =>
  ({ id, vault_id: V.vaultId, item_key: "k", data: `data-${id}`, revision: 1, deleted_at: null, created_at: 0, updated_at: 0, ...extra }) as SyncItemRow;
const mapped = (name: string) => (V.items[name] as unknown as SyncItemRow[]).map((r) => manifestItem(r));
const LINK_A = "a".repeat(43);
const LINK_B = "b".repeat(43);

test("vaultManifest vectors: every row's link, and every verdict, through the core the extension bundles", () => {
  expect(V, "testdata/vectors.json vaultManifest").toBeDefined();
  expect(V.checks.length).toBeGreaterThan(50);
  for (const [name, m] of Object.entries(V.manifests)) {
    if (m.link !== null) expect(core.manifestLink(m.manifest_seq, m.manifest_prev!, m.manifest!), name).toBe(m.link);
  }
  const k = keys();
  for (const c of V.checks) {
    const m = V.manifests[c.manifest]!;
    const got = k[c.key].manifestVerify(V.vaultId, c.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, c.remembered?.version, c.remembered?.link, c.log, V.items[c.items]) as Check;
    expect(got, c.name).toStrictEqual(c.expected);
    // The same through the extension's own wrapper, from a vault row and the rows as it maps them. A "need_log" with a
    // log in hand can't happen; with none it is passed on for the caller to fetch the log.
    const mine = verifyVault(k[c.key], rowOf(c.manifest, c.keyEpoch), c.remembered ?? undefined, mapped(c.items), c.log);
    expect(mine, `wrapper: ${c.name}`).toStrictEqual({ status: c.expected.status, version: c.expected.version, link: c.expected.link });
  }
  for (const status of ["none", "ok", "rollback", "mismatch", "incomplete", "need_log"])
    expect(
      V.checks.some((c) => c.expected.status === status),
      status,
    ).toBe(true);
});

test("vaultManifest vectors: rows whose `deleted_at` is no time are refused by every entry point (a mismatch here)", () => {
  const k = key();
  const c = current();
  expect(V.malformed.map((m) => m.deletedAt)).toContain(0);
  for (const m of V.malformed) {
    const name = `deleted_at ${JSON.stringify(m.deletedAt)}`;
    expect(() => k.manifestVerify(V.vaultId, V.keyEpoch, c.manifest_seq, c.manifest_prev, c.manifest, null, null, null, m.items), name).toThrow();
    expect(() => k.manifestStart(V.vaultId, V.keyEpoch, 1, null, m.items), name).toThrow();
    expect(
      verifyVault(
        k,
        rowOf("current"),
        undefined,
        (m.items as SyncItemRow[]).map((r) => manifestItem(r)),
      ).status,
      name,
    ).toBe("mismatch");
  }
});

test("vaultManifest vectors: every kind of write gives the next manifest, which names the one it replaces and which the core accepts for the rows after it", () => {
  const k = key();
  const c = current();
  expect(V.writes.map((w) => w.name)).toStrictEqual(expect.arrayContaining(["create", "edit", "trash", "restore", "delete for good"]));
  for (const w of V.writes) {
    const next = entryOf(V.vaultId, k.manifestNext(V.vaultId, V.keyEpoch, c.manifest_seq, c.manifest_prev, c.manifest, w.removed, w.added));
    expect([next.seq, next.prev], w.name).toStrictEqual([w.expected.seq, w.expected.prev]);
    expect(next.prev, w.name).toBe(c.link);
    expect(next.link, w.name).toBe(core.manifestLink(next.seq, next.prev, next.sealed));
    const after = k.manifestVerify(V.vaultId, V.keyEpoch, next.seq, next.prev, next.sealed, c.manifest_seq, c.link, null, w.after) as Check;
    expect(after, w.name).toStrictEqual({ status: "ok", version: next.seq, link: next.link, live: w.expected.live, trashed: w.expected.trashed });
    // The manifest from before no longer describes those rows (unless the write changed nothing).
    if (w.name !== "nothing")
      expect((k.manifestVerify(V.vaultId, V.keyEpoch, c.manifest_seq, c.manifest_prev, c.manifest, c.manifest_seq, c.link, null, w.after) as Check).status, w.name).toBe("mismatch");
  }
  expect(core.manifestDataHash(V.items.full![0]!.data as string)).toBe(V.terms[0]!.dataSha256);
});

test("vaultManifest vectors: a first manifest, a key replacement's and a baseline each name their predecessor and check out for the device that made them", () => {
  const k = keys();
  for (const s of V.starts) {
    const w = entryOf(V.vaultId, k[s.key].manifestStart(V.vaultId, s.keyEpoch, s.version, s.prev, V.items[s.items]));
    expect({ seq: w.seq, prev: w.prev }, s.name).toStrictEqual(s.expected);
    const check = k[s.key].manifestVerify(V.vaultId, s.keyEpoch, w.seq, w.prev, w.sealed, s.remembered?.version, s.remembered?.link, null, V.items[s.items]) as Check;
    expect([check.status, check.link], s.name).toStrictEqual(["ok", w.link]);
  }
  expect(() => k.main.manifestStart(V.vaultId, V.keyEpoch, 9, null, V.items.noHash), "a row with neither data nor hash").toThrow();
  // Half a memory is never passed on: the core throws for it, and the wrapper reads it as nothing remembered.
  const c = current();
  expect(() => k.main.manifestVerify(V.vaultId, V.keyEpoch, c.manifest_seq, c.manifest_prev, c.manifest, 3, null, null, V.items.full)).toThrow();
  expect(verifyVault(k.main, rowOf("current"), { version: 3, link: "short" } as Remembered, mapped("full")).status).toBe("ok");
});

test("REVIEW PoC (was: passes): a server row carrying served_sha256 never replaces the row's data in the check", () => {
  const k = key();
  const ok = V.checks.find((c) => c.name === "first sight")!;
  const rows = V.items[ok.items] as unknown as (SyncItemRow & { data?: string })[];
  const victim = rows.find((r) => typeof r.data === "string" && !r.deleted_at)!;
  const row = rowOf(ok.manifest);
  expect(
    verifyVault(
      k,
      row,
      undefined,
      rows.map((r) => manifestItem(r)),
    ).status,
  ).toBe("ok");
  // Tampered data alone: mismatch.
  const tampered = rows.map((r) => (r === victim ? { ...r, data: "OLDER-CIPHERTEXT" } : r));
  expect(
    verifyVault(
      k,
      row,
      undefined,
      tampered.map((r) => manifestItem(r)),
    ).status,
  ).toBe("mismatch");
  // Tampered data + the server-supplied field with the hash of the real data: still a mismatch (the field isn't read).
  const masked = rows.map((r) => (r === victim ? { ...r, data: "OLDER-CIPHERTEXT", [SERVED_HASH]: core.manifestDataHash(victim.data!) } : r));
  expect(manifestItem(masked.find((r) => r.id === victim.id) as SyncItemRow)).toStrictEqual({ id: victim.id, deleted_at: null, data: "OLDER-CIPHERTEXT" });
  expect(
    verifyVault(
      k,
      row,
      undefined,
      masked.map((r) => manifestItem(r as SyncItemRow)),
    ).status,
  ).toBe("mismatch");
  expect(verifyVault(k, row, undefined, manifestItems({ items: new Map(masked.map((r) => [r.id, r as SyncItemRow])) }).get(V.vaultId) ?? []).status).toBe("mismatch");
  // And it is deleted from every row that comes from outside.
  stripPrivate(masked);
  expect(masked.some((r) => SERVED_HASH in r)).toBe(false);
  stripPrivate(null);
  stripPrivate([null, 3, "x"]);
});

test("anything the core can't judge is a mismatch: rows it refuses (an id twice), a key that throws, an answer that isn't a verdict, a second 'need_log'", () => {
  const k = key();
  const row = rowOf("current");
  const rows = mapped("full");
  const mismatch = { status: "mismatch", version: 0, link: null };
  expect(verifyVault(k, row, undefined, [...rows, rows[0]!])).toStrictEqual(mismatch);
  expect(verifyVault({ manifestVerify: () => ({ status: "fine" }) }, row, undefined, rows)).toStrictEqual(mismatch);
  expect(verifyVault({ manifestVerify: () => null }, row, undefined, rows)).toStrictEqual(mismatch);
  expect(verifyVault({ manifestVerify: () => ({ status: "ok", version: 3, link: "no link" }) }, row, undefined, rows), "an ok without a link to remember").toStrictEqual(mismatch);
  expect(verifyVault({ manifestVerify: () => ({ status: "need_log", version: 1, link: LINK_A }) }, row, undefined, rows).status, "no log yet: the caller fetches it").toBe("need_log");
  expect(verifyVault({ manifestVerify: () => ({ status: "need_log", version: 1, link: LINK_A }) }, row, undefined, rows, []), "never asked twice").toStrictEqual(mismatch);
  // A manifest that isn't text, no predecessor, or a version that isn't one (read as none, so a remembered version says rollback).
  expect(verifyVault(k, vaultRow({ ...row, manifest: 7 }), undefined, rows).status).toBe("mismatch");
  expect(verifyVault(k, vaultRow({ ...row, manifest_prev: undefined }), undefined, rows).status).toBe("mismatch");
  expect(verifyVault(k, vaultRow({ ...row, manifest_seq: "3" }), { version: 3, link: current().link }, rows).status).toBe("rollback");
  expect(verifyVault(k, vaultRow({ ...row, manifest_seq: "3" }), undefined, rows).status).toBe("none");
});

test("vault rows: the manifest fields as read; item rows: data, a summary's hash, a kept copy's served hash (from the map, never the row); in the trash = deleted_at is not null", () => {
  expect(manifestSeqOf(vaultRow())).toBe(0);
  expect(manifestSeqOf(vaultRow({ manifest_seq: 4 }))).toBe(4);
  for (const bad of [-1, 1.5, "4", null, Number.MAX_SAFE_INTEGER + 2]) expect(manifestSeqOf(vaultRow({ manifest_seq: bad }))).toBe(0);
  expect(manifestTextOf(vaultRow({ manifest: "abc" }))).toBe("abc");
  for (const bad of [null, "", 3, {}]) expect(manifestTextOf(vaultRow({ manifest: bad }))).toBe(null);
  expect(manifestPrevOf(vaultRow({ manifest_prev: LINK_A }))).toBe(LINK_A);
  for (const bad of [undefined, null, "", 3, {}]) expect(manifestPrevOf(vaultRow({ manifest_prev: bad }))).toBe(null);
  expect(manifestReady(vaultRow({ manifest_ok: true }))).toBe(true);
  for (const bad of [undefined, false, 1, "true"]) expect(manifestReady(vaultRow({ manifest_ok: bad }))).toBe(false);

  expect(manifestItem(itemRow("a"))).toStrictEqual({ id: "a", deleted_at: null, data: "data-a" });
  expect(manifestItem(itemRow("a", { deleted_at: 5 }))).toStrictEqual({ id: "a", deleted_at: 5, data: "data-a" });
  // A trash summary: no data, the server's hash.
  expect(manifestItem(itemRow("a", { deleted_at: 5, data: undefined, item_key: undefined, data_sha256: "h" }))).toStrictEqual({ id: "a", deleted_at: 5, data_sha256: "h" });
  // One from before the server sent hashes: neither (the core says "incomplete").
  expect(manifestItem(itemRow("a", { deleted_at: 5, data: undefined }))).toStrictEqual({ id: "a", deleted_at: 5 });
  // A newer copy this browser kept instead of the server's older one: the server's data counts, by its hash.
  expect(manifestItem(itemRow("a"), "served")).toStrictEqual({ id: "a", deleted_at: null, data_sha256: "served" });
  // A `deleted_at` of 0 goes to the core as it is (it refuses it): never read as "live" here.
  expect(manifestItem(itemRow("a", { deleted_at: 0 })).deleted_at).toBe(0);

  const snap = { items: new Map([itemRow("a"), itemRow("b", { vault_id: "other" }), itemRow("c", { deleted_at: 1 })].map((r) => [r.id, r])) };
  const by = manifestItems(snap, new Map([["c", "served-c"]]));
  expect(by.get(V.vaultId)).toStrictEqual([
    { id: "a", deleted_at: null, data: "data-a" },
    { id: "c", deleted_at: 1, data_sha256: "served-c" },
  ]);
  expect(by.get("other")?.map((i) => i.id)).toStrictEqual(["b"]);

  expect([null, undefined].map((d) => isTrashed({ deleted_at: d }))).toStrictEqual([false, false]);
  expect(
    [5, 0, -1, "x", false, 0.5].map((d) => isTrashed({ deleted_at: d })),
    "anything but null is the trash",
  ).toStrictEqual([true, true, true, true, true, true]);
});

test("memory: version + link per vault; the higher version wins, a link is never replaced at its version; old formats and half entries are nothing; vaults that are gone stay", () => {
  const m = readManifestMemory({
    a: { version: 3, link: LINK_A },
    old: 3,
    half: { version: 2 },
    bad: { version: 2, link: "short" },
    zero: { version: 0, link: LINK_A },
    frac: { version: 1.5, link: LINK_A },
    f: { version: 9, link: LINK_B },
  });
  expect([...m]).toStrictEqual([
    ["a", { version: 3, link: LINK_A }],
    ["f", { version: 9, link: LINK_B }],
  ]);
  rememberManifest(m, "a", 2, LINK_B);
  expect(m.get("a"), "never lowered").toStrictEqual({ version: 3, link: LINK_A });
  rememberManifest(m, "a", 3, LINK_B);
  expect(m.get("a"), "the same version keeps the link it has").toStrictEqual({ version: 3, link: LINK_A });
  rememberManifest(m, "a", 4, LINK_B);
  rememberManifest(m, "new", 1, LINK_A);
  for (const bad of [0, -3, 1.5, Number.NaN]) rememberManifest(m, "bad", bad, LINK_A);
  for (const bad of [null, undefined, "", "short", 7]) rememberManifest(m, "bad", 5, bad);
  expect(storedManifestMemory(m)).toStrictEqual({ a: { version: 4, link: LINK_B }, f: { version: 9, link: LINK_B }, new: { version: 1, link: LINK_A } });
  for (const none of [null, undefined, {}, [], "x", { a: 3 }]) expect(readManifestMemory(none).size).toBe(0);
  expect([isLink(LINK_A), isLink("A".repeat(42)), isLink(`${"A".repeat(42)}=`), isLink(null)]).toStrictEqual([true, false, false, false]);
  // Two writers: each vault's higher version; at the same version the one already there.
  const there: ManifestMemory = new Map([
    ["a", { version: 2, link: LINK_A }],
    ["b", { version: 5, link: LINK_A }],
    ["same", { version: 4, link: LINK_A }],
  ]);
  const mine: ManifestMemory = new Map([
    ["a", { version: 3, link: LINK_B }],
    ["c", { version: 1, link: LINK_B }],
    ["same", { version: 4, link: LINK_B }],
  ]);
  expect(Object.fromEntries(mergeManifestMemory(there, mine))).toStrictEqual({
    a: { version: 3, link: LINK_B },
    b: { version: 5, link: LINK_A },
    c: { version: 1, link: LINK_B },
    same: { version: 4, link: LINK_A },
  });
});

test("the manifest log: pages are followed while the server says more, at most five requests; no log, or one that doesn't end, doesn't connect; a failure is passed on", async () => {
  const asked: number[] = [];
  const pages = (list: unknown[]) => async (after: number) => {
    asked.push(after);
    return list.shift();
  };
  expect(await collectLog(3, pages([{ entries: [{ seq: 4 }, { seq: 5 }], more: false }]))).toStrictEqual([{ seq: 4 }, { seq: 5 }]);
  expect(asked).toStrictEqual([3]);
  asked.length = 0;
  expect(
    await collectLog(
      3,
      pages([
        { entries: [{ seq: 4 }], more: true },
        { entries: [{ seq: 5 }, { seq: 6 }], more: true },
        { entries: [{ seq: 7 }], more: false },
      ]),
    ),
  ).toStrictEqual([{ seq: 4 }, { seq: 5 }, { seq: 6 }, { seq: 7 }]);
  expect(asked, "each page from the last entry of the one before").toStrictEqual([3, 4, 6]);
  // A 404 or 400 (the caller's null), an answer that isn't a log: it doesn't connect.
  for (const none of [null, undefined, {}, { entries: "x" }, []]) expect(await collectLog(3, async () => none)).toBe(null);
  // "More" forever: five requests, then it doesn't connect.
  let n = 3;
  asked.length = 0;
  expect(
    await collectLog(3, async (after) => {
      asked.push(after);
      return { entries: [{ seq: ++n }], more: true };
    }),
  ).toBe(null);
  expect(asked).toHaveLength(LOG_REQUESTS);
  expect(LOG_REQUESTS).toBe(5);
  // "More" that leads nowhere: not asked again.
  expect(await collectLog(3, async () => ({ entries: [{ seq: 3 }], more: true }))).toBe(null);
  expect(await collectLog(3, async () => ({ entries: [], more: true }))).toBe(null);
  // No answer (the network, a 5xx): the caller's failure, never "no log".
  await expect(collectLog(3, async () => Promise.reject(new Error("offline")))).rejects.toThrow("offline");
});

test("starting a vault's first manifest: only when the server keeps them and says every app can, with write access, nothing seen before, every row counted and no kept newer copy", () => {
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
  expect(mayStart({ ...ok, remembered: { version: 4, link: LINK_A } }), "one was seen here: its absence is a rollback, never a fresh start").toBe(false);
  for (const status of ["ok", "rollback", "mismatch", "incomplete", "unchecked", undefined] as const) expect(mayStart({ ...ok, status }), String(status)).toBe(false);
  expect(mayStart({ ...ok, items: [...items, { id: "c", deleted_at: 3 }] }), "a row with neither data nor hash").toBe(false);
  expect(mayStart({ ...ok, kept: true }), "the server sent an older version of an item of this vault").toBe(false);
  expect(mayStart({ ...ok, items: [] }), "an empty vault").toBe(true);
});

test("old trash: due only when the server's rule says so AND this browser saw the item in the trash for the whole period AND the two clocks agree within a day", () => {
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
    itemRow("zero", { deleted_at: 0 }),
    itemRow("unseen", { deleted_at: 5 }),
    itemRow("justSeen", { deleted_at: 5 }),
  ];
  const long = now - 40 * day;
  const seen = new Map([
    ["live", long],
    ["fresh", long],
    ["edge", long],
    ["due", long],
    ["old", now - 30 * day],
    ["elsewhere", long],
    ["odd", long],
    ["zero", long],
    ["justSeen", now - 30 * day + 1],
  ]);
  const served = { serverTime: now, trashDays: 30 };
  // The server's rule: `deleted_at + trash_days days <= server_time` (the edge counts).
  expect(dueTrash(rows, V.vaultId, served, seen, now).map((r) => r.id)).toStrictEqual(["edge", "due", "old"]);
  // Nothing this browser hasn't watched for the period, whatever the server says: also with a clock or a setting made up.
  expect(dueTrash(rows, V.vaultId, served, new Map(), now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: 1 }, new Map([["due", now - day + 1]]), now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: Number.MAX_SAFE_INTEGER, trashDays: 1 }, seen, now), "a server clock far from this browser's").toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now + CLOCK_TOLERANCE + 1, trashDays: 30 }, seen, now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now - CLOCK_TOLERANCE - 1, trashDays: 30 }, seen, now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now + CLOCK_TOLERANCE, trashDays: 30 }, seen, now).length, "a day apart is fine").toBeGreaterThan(0);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: 0 }, seen, now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: null }, seen, now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: null, trashDays: 30 }, seen, now)).toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: Number.MAX_SAFE_INTEGER }, seen, now), "a period no number holds").toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, served, seen, Number.NaN)).toStrictEqual([]);
  expect(readServed({ server_time: now, trash_days: 30 })).toStrictEqual({ serverTime: now, trashDays: 30 });
  expect(readServed({ server_time: "now", trash_days: -1 })).toStrictEqual({ serverTime: null, trashDays: null });
  expect(readServed(null)).toStrictEqual({ serverTime: null, trashDays: null });
  // One request names at most 250 items, fewer when the server's limit is lower.
  expect(purgeBatch({ max_import_items: 40 })).toBe(40);
  expect(purgeBatch({ max_import_items: 5000 })).toBe(250);
  for (const none of [null, {}, { max_import_items: 0 }, { max_import_items: "9" }]) expect(purgeBatch(none)).toBe(250);
});

test("first seen in the trash: noted once by this browser's clock, kept while the row stays there, forgotten when it is live again or gone", () => {
  let seen = noteTrash(new Map(), [itemRow("a", { deleted_at: 5 }), itemRow("b"), itemRow("c", { deleted_at: 0 })], 1000);
  expect(Object.fromEntries(seen)).toStrictEqual({ a: 1000, c: 1000 });
  seen = noteTrash(seen, [itemRow("a", { deleted_at: 5 }), itemRow("b", { deleted_at: 9 })], 2000);
  expect(Object.fromEntries(seen), "the first time stays; gone rows go").toStrictEqual({ a: 1000, b: 2000 });
  // Out of the trash and back: it starts again.
  seen = noteTrash(seen, [itemRow("a"), itemRow("b", { deleted_at: 9 })], 3000);
  seen = noteTrash(seen, [itemRow("a", { deleted_at: 7 }), itemRow("b", { deleted_at: 9 })], 4000);
  expect(Object.fromEntries(seen)).toStrictEqual({ a: 4000, b: 2000 });
  // A clock set back never makes an item look longer in the trash than it was seen there.
  expect(Object.fromEntries(noteTrash(seen, [itemRow("b", { deleted_at: 9 })], 500))).toStrictEqual({ b: 2000 });
  expect(dueTrash([itemRow("b", { deleted_at: 9 })], V.vaultId, { serverTime: 500, trashDays: 1 }, new Map([["b", 2000]]), 500)).toStrictEqual([]);
  expect(noteTrash(seen, [], Number.NaN), "no clock: nothing changes").toStrictEqual(seen);
  expect(Object.fromEntries(readTrashSeen({ a: 5, b: -1, c: "x", d: 1.5 }))).toStrictEqual({ a: 5 });
  for (const none of [null, undefined, [], "x"]) expect(readTrashSeen(none).size).toBe(0);
});

test("the numbers of an answer: seq, manifest_seq, key_epoch and deleted_at must be whole numbers from 0 to 2^53 - 1 where present", () => {
  const ok = { vaults: [{ seq: 0, manifest_seq: 3, key_epoch: 2 }, { key_epoch: null }, {}], items: [{ deleted_at: null }, { deleted_at: 0 }, { deleted_at: Number.MAX_SAFE_INTEGER }, {}] };
  expect(validNumbers(ok)).toBe(true);
  for (const bad of [-1, 1.5, "3", Number.MAX_SAFE_INTEGER + 1, Number.NaN, Number.POSITIVE_INFINITY, true, {}]) {
    for (const field of ["seq", "manifest_seq", "key_epoch"]) expect(validNumbers({ vaults: [{ [field]: bad }], items: [] }), `${field} ${String(bad)}`).toBe(false);
    expect(validNumbers({ vaults: [], items: [{ deleted_at: bad }] }), `deleted_at ${String(bad)}`).toBe(false);
  }
  expect(validNumbers({})).toBe(true);
});

test("an answer behind an own write: a vault's number below the one after that write", () => {
  const vaults = [vaultRow({ seq: 7 }), vaultRow({ id: "other", seq: 2 })];
  expect(behindOwn({}, vaults)).toBe(false);
  expect(behindOwn({ [V.vaultId]: 7 }, vaults)).toBe(false);
  expect(behindOwn({ [V.vaultId]: 8 }, vaults)).toBe(true);
  expect(behindOwn({ other: 3 }, vaults)).toBe(true);
  expect(behindOwn({ gone: 9 }, vaults), "a vault the answer doesn't list").toBe(false);
});

test("what a write sends and what it leaves in the copy: body entries with prev (never the link), the query of a request without a body, the row's three manifest fields", () => {
  const built = { seq: 4, prev: LINK_A, sealed: "s", link: LINK_B };
  const entry = entryOf("v", built);
  expect(entry).toStrictEqual({ vault_id: "v", seq: 4, prev: LINK_A, sealed: "s", link: LINK_B });
  expect(sentEntry(entry)).toStrictEqual({ vault_id: "v", seq: 4, prev: LINK_A, sealed: "s" });
  for (const bad of [null, {}, { ...built, seq: 0 }, { ...built, sealed: "" }, { ...built, seq: "4" }, { ...built, prev: "x" }, { ...built, prev: undefined }, { ...built, link: null }, "sealed-text"])
    expect(() => entryOf("v", bad)).toThrow();
  expect(writeQuery(undefined, null), "a vault without a manifest: the request as it always was").toBe("");
  expect(writeQuery(12, { ...entry, sealed: "Ab-_9" })).toBe(`?revision=12&manifest_seq=4&manifest_prev=${LINK_A}&manifest=Ab-_9`);
  expect(writeQuery(undefined, { ...entry, sealed: "a b" })).toBe(`?manifest_seq=4&manifest_prev=${LINK_A}&manifest=a%20b`);

  const snap: Snapshot = { revision: 1, cursor: "c", user: {} as never, bundle: {} as never, vaults: [vaultRow(), vaultRow({ id: "other" })], items: new Map(), invitations: [], own: { other: 2 } };
  const mine = { ...entry, vault_id: V.vaultId };
  const next = withManifest(snap, mine, 8);
  expect([manifestSeqOf(next.vaults[0]!), manifestTextOf(next.vaults[0]!), manifestPrevOf(next.vaults[0]!), manifestSeqOf(next.vaults[1]!)]).toStrictEqual([4, "s", LINK_A, 0]);
  expect(next.own).toStrictEqual({ other: 2, [V.vaultId]: 8 });
  expect(withManifest(snap, mine).own, "with an item write the vault number comes from that write").toStrictEqual({ other: 2 });
  expect(manifestSeqOf(snap.vaults[0]!), "the snapshot given isn't changed").toBe(0);
});

test("the warning: the contract's words, for rollback and mismatch alike, naming the vaults; nothing for the other states (an unchecked vault shows none)", () => {
  expect(MANIFEST_WARNING_TEXT).toBe("Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date.");
  expect(MANIFEST_REVIEW_TEXT).toBe("Open the web vault or the desktop app to review this vault.");
  expect(MANIFEST_HELD_TEXT).toBe("This vault can't be changed until its warning is resolved.");
  expect(MANIFEST_BUSY_TEXT).toBe("This vault changed on another device. Try again.");
  expect(["rollback", "mismatch"].map((s) => unresolved(s as never))).toStrictEqual([true, true]);
  expect(["none", "ok", "incomplete", "unchecked", undefined].map((s) => unresolved(s as never))).toStrictEqual([false, false, false, false, false]);
  expect(["incomplete", "unchecked"].map((s) => unsettled(s as never))).toStrictEqual([true, true]);
  expect(["none", "ok", "rollback", "mismatch", undefined].map((s) => unsettled(s as never))).toStrictEqual([false, false, false, false, false]);
  const vaults = [
    { id: "b", name: "Team" },
    { id: "a", name: "Personal" },
    { id: "c", name: "Fine" },
    { id: "d", name: "Waiting" },
  ];
  expect(
    manifestNotice(
      vaults,
      new Map([
        ["c", "ok"],
        ["d", "unchecked"],
      ]),
    ),
  ).toBe(null);
  const n = manifestNotice(
    vaults,
    new Map([
      ["a", "mismatch"],
      ["b", "rollback"],
      ["c", "ok"],
      ["d", "unchecked"],
    ]),
  );
  expect(n).toStrictEqual({ text: MANIFEST_WARNING_TEXT, review: MANIFEST_REVIEW_TEXT, vaults: [vaults[0], vaults[1]], key: '["a","b"]' });
});
