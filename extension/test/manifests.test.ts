// Vault manifests, the pure parts (background/manifests.ts) with the real core:
// - the `vaultManifest` section of testdata/vectors.json through the WASM build the extension bundles: every verdict
//   (the chain included: links, `need_log`, logs, forks, key replacements, baselines), rows the core must refuse,
//   every kind of write and every kind of start;
// - the rows as the core counts them (data, a trash summary's hash, a kept newer copy's served hash, which is never
//   read from the row), the one "in the trash" predicate;
// - what this browser remembers (version + link; never lowered, a link never replaced at its version, old formats
//   and half entries are nothing);
// - the manifest log (paging, its cap), starting a manifest, the old-trash selection (bounded by what this browser
//   saw itself), the numbers of an answer, the query of a request without a body;
// - review round 2: `manifestAccept` (the vectors' `accepts`), memories the core refuses (`badMemories`), logs passed
//   as they came (`check.log` raw, rubbish included) and only well-typed entries from the wire, the memory's
//   `accepts` counter (replace, forget, merge), no start over a row that doesn't open, the strict trash rule and its
//   7-day floor, and what each warning offers.

import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";
import { expect, test } from "vitest";
import {
  acceptedEntry,
  acceptsIn,
  acceptVault,
  behindOwn,
  CLOCK_TOLERANCE,
  collectLog,
  dueTrash,
  entryOf,
  isLink,
  isLogEntry,
  isTrashed,
  LOG_REQUESTS,
  MANIFEST_ACCEPT_ACTION,
  MANIFEST_ACCEPT_BODY,
  MANIFEST_ACCEPT_TITLE,
  MANIFEST_BUSY_TEXT,
  MANIFEST_HELD_TEXT,
  MANIFEST_ITEM_READER_TEXT,
  MANIFEST_ITEM_TEXT,
  MANIFEST_ITEM_WHERE_TEXT,
  MANIFEST_READER_TEXT,
  MANIFEST_REVIEW_TEXT,
  MANIFEST_UNCHECKED_TEXT,
  MANIFEST_WARNING_TEXT,
  type ManifestItem,
  type ManifestMemory,
  MEMORY_RESET_ACTION,
  MEMORY_RESET_BODY,
  MEMORY_UNREADABLE_TEXT,
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
  readStanding,
  readTrashSeen,
  rememberedOf,
  rememberManifest,
  rowStampOf,
  SERVED_HASH,
  sentEntry,
  storedManifestMemory,
  stripPrivate,
  TRASH_FLOOR_DAYS,
  unresolved,
  unsettled,
  validNumbers,
  verifyVault,
  warningOf,
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
  accepts: { name: string; manifest: string; key: KeyName; keyEpoch: number; items: string; expected: Check }[];
  badMemories: { version: number; link: string }[];
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

test("ROUND 2 vectors: a log goes to the core as it came (raw JSON, rubbish and all); rubbish is skipped, never fatal, and never a pass on its own", () => {
  const k = keys();
  const byName = (name: string) => V.checks.find((c) => c.name === name)!;
  const around = byName("a log with rubbish around the real entries");
  const alone = byName("a log of rubbish alone");
  expect([around.expected.status, alone.expected.status]).toStrictEqual(["ok", "mismatch"]);
  for (const c of [around, alone]) {
    // The vector's log really holds things that are no entries (it would not survive a typed decoder).
    expect(
      c.log!.some((e) => !isLogEntry(e)),
      c.name,
    ).toBe(true);
    const m = V.manifests[c.manifest]!;
    // Re-serialised from the vector file and parsed again: plain JSON values, exactly as a server's answer arrives.
    const raw = JSON.parse(JSON.stringify(c.log)) as unknown[];
    expect(k[c.key].manifestVerify(V.vaultId, c.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, c.remembered?.version, c.remembered?.link, raw, V.items[c.items]), c.name).toStrictEqual(
      c.expected,
    );
    // What the extension passes on (only the well-typed entries, each as it came) gives the same verdict.
    const typed = raw.filter(isLogEntry);
    expect(
      (k[c.key].manifestVerify(V.vaultId, c.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, c.remembered?.version, c.remembered?.link, typed, V.items[c.items]) as Check).status,
      c.name,
    ).toBe(c.expected.status);
  }
  // For every check with a log: the well-typed entries alone give the verdict of the whole log.
  for (const c of V.checks.filter((x) => x.log)) {
    const m = V.manifests[c.manifest]!;
    const typed = (c.log as unknown[]).filter(isLogEntry);
    expect(
      (k[c.key].manifestVerify(V.vaultId, c.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, c.remembered?.version, c.remembered?.link, typed, V.items[c.items]) as Check).status,
      c.name,
    ).toBe(c.expected.status);
  }
  // A log that isn't a list still throws (a mismatch in the wrapper).
  const cur = current();
  expect(() => k.main.manifestVerify(V.vaultId, V.keyEpoch, cur.manifest_seq, cur.manifest_prev, cur.manifest, 1, V.manifests.first!.link, "log" as never, V.items.full)).toThrow();
  // One version above the remembered one never needs a log: on the remembered history it is "ok", else a mismatch at once.
  expect(byName("one step ahead").expected.status).toBe("ok");
  expect(byName("joined one version later, no log needed").expected.status).toBe("mismatch");
  for (const c of V.checks.filter((x) => x.expected.status === "need_log")) {
    expect(V.manifests[c.manifest]!.manifest_seq - (c.remembered?.version ?? 0), c.name).toBeGreaterThanOrEqual(2);
  }
  expect([isLogEntry({ seq: 3, prev: "p", digest: "d" }), isLogEntry({ seq: 3.0, prev: "", digest: "" })]).toStrictEqual([true, true]);
  for (const bad of [
    null,
    7,
    "x",
    [],
    {},
    { seq: 0, prev: "p", digest: "d" },
    { seq: 1.5, prev: "p", digest: "d" },
    { seq: "3", prev: "p", digest: "d" },
    { seq: 3, prev: 1, digest: "d" },
    { seq: 3, prev: "p" },
    { seq: 2 ** 53, prev: "p", digest: "d" },
  ])
    expect(isLogEntry(bad), JSON.stringify(bad)).toBe(false);
});

test("ROUND 2 vectors: manifestAccept (the check with nothing remembered) for every `accepts` entry, through the core and through the extension's wrapper", () => {
  const k = keys();
  expect(V.accepts.length).toBeGreaterThan(10);
  for (const a of V.accepts) {
    const m = V.manifests[a.manifest];
    const row = m ?? { manifest_seq: 0, manifest_prev: null, manifest: null };
    const got = k[a.key].manifestAccept(V.vaultId, a.keyEpoch, row.manifest_seq, row.manifest_prev, row.manifest, V.items[a.items]) as Check;
    expect(got, a.name).toStrictEqual(a.expected);
    const mine = acceptVault(k[a.key], vaultRow({ manifest: row.manifest, manifest_seq: row.manifest_seq, manifest_prev: row.manifest_prev, key_epoch: a.keyEpoch }), mapped(a.items));
    if (a.expected.status === "ok") expect(mine, `wrapper: ${a.name}`).toStrictEqual({ status: "ok", version: a.expected.version, link: a.expected.link });
    else expect(mine, `wrapper: ${a.name}`).toStrictEqual({ status: a.expected.status === "none" ? "none" : "no" });
  }
  for (const status of ["ok", "none", "mismatch"])
    expect(
      V.accepts.some((a) => a.expected.status === status),
      status,
    ).toBe(true);
  // An older state of the vault and a baseline are both acceptable: that is what "Use the server's copy" is for.
  expect(V.accepts.find((a) => a.name === "an older state of the vault (a restored backup)")?.expected.status).toBe("ok");
  // Anything the core can't judge, and any answer that isn't one, is never acceptable.
  const row = rowOf("current");
  expect(
    acceptVault(
      {
        manifestAccept: () => {
          throw new Error("x");
        },
      },
      row,
      [],
    ),
  ).toStrictEqual({ status: "no" });
  for (const odd of [
    null,
    {},
    { status: "ok" },
    { status: "ok", version: 3, link: "short" },
    { status: "ok", version: 0, link: LINK_A },
    { status: "ok", version: 3, link: "A".repeat(43) },
    { status: "incomplete" },
    { status: "need_log" },
    { status: "rollback" },
  ])
    expect(acceptVault({ manifestAccept: () => odd }, row, []), JSON.stringify(odd)).toStrictEqual({ status: "no" });
  expect(acceptVault({ manifestAccept: () => ({ status: "none", version: 0, link: null }) }, row, [])).toStrictEqual({ status: "none" });
});

test("ROUND 2 vectors: memories the core refuses (`badMemories`: the all-zero link, half entries) throw there, and are 'nothing remembered' here, never passed on", () => {
  const k = key();
  const c = current();
  expect(V.badMemories.length).toBeGreaterThan(3);
  expect(V.badMemories.some((b) => b.link === "A".repeat(43))).toBe(true);
  for (const b of V.badMemories) {
    const name = JSON.stringify(b);
    expect(() => k.manifestVerify(V.vaultId, V.keyEpoch, c.manifest_seq, c.manifest_prev, c.manifest, b.version, b.link, null, V.items.full), name).toThrow();
    // As stored: not an entry, so nothing remembered; never written either.
    expect(rememberedOf(readManifestMemory({ v: b }), "v"), name).toBeUndefined();
    const m: ManifestMemory = new Map();
    rememberManifest(m, "v", b.version, b.link);
    expect(m.size, name).toBe(0);
    expect(acceptedEntry(b as Remembered, 0), name).toStrictEqual({ accepts: 1 });
    // The wrapper reads it as nothing remembered (first sight), never as a memory.
    expect(verifyVault(k, rowOf("current"), b as Remembered, mapped("full")).status, name).toBe("ok");
  }
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
  // Round 2: nothing jumps. Every start that names a predecessor is exactly one version above it.
  const linked = new Map(
    Object.values(V.manifests)
      .filter((m) => m.link)
      .map((m) => [m.link as string, m.manifest_seq]),
  );
  for (const s of V.starts.filter((x) => x.prev !== null)) expect(s.version, s.name).toBe((linked.get(s.prev as string) ?? Number.NaN) + 1);
  for (const s of V.starts.filter((x) => x.prev === null)) expect(s.version, s.name).toBe(1);
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

test("ROUND 2 memory: `accepts` counts acceptances; replace (also downwards) and forget come only from an acceptance; the merge goes by accepts, then version, then what is stored", () => {
  // Replace: whatever was there, also a higher version; the counter goes one above the floor given.
  expect(acceptedEntry({ version: 2, link: LINK_A }, 0)).toStrictEqual({ version: 2, link: LINK_A, accepts: 1 });
  expect(acceptedEntry({ version: 2, link: LINK_A }, 4)).toStrictEqual({ version: 2, link: LINK_A, accepts: 5 });
  // Forget (the server shows no manifest): no version or link, and the counter stays to outrank older copies.
  expect(acceptedEntry(null, 2)).toStrictEqual({ accepts: 3 });
  const m: ManifestMemory = new Map([
    ["down", { version: 9, link: LINK_A }],
    ["gone", { version: 4, link: LINK_A, accepts: 1 }],
  ]);
  m.set("down", acceptedEntry({ version: 2, link: LINK_B }, acceptsIn(m, "down")));
  m.set("gone", acceptedEntry(null, acceptsIn(m, "gone")));
  expect(rememberedOf(m, "down")).toStrictEqual({ version: 2, link: LINK_B });
  expect(rememberedOf(m, "gone"), "forgotten is nothing remembered").toBeUndefined();
  expect([acceptsIn(m, "down"), acceptsIn(m, "gone"), acceptsIn(m, "never")]).toStrictEqual([1, 2, 0]);
  // An ordinary advance keeps the counter, and starts again from nothing after a forget.
  rememberManifest(m, "down", 3, LINK_A);
  rememberManifest(m, "down", 2, LINK_B);
  rememberManifest(m, "gone", 1, LINK_B);
  expect(storedManifestMemory(m)).toStrictEqual({ down: { version: 3, link: LINK_A, accepts: 1 }, gone: { version: 1, link: LINK_B, accepts: 2 } });
  // As stored and read back: entries with a counter, a forgotten one, and rubbish around a counter.
  const read = readManifestMemory({
    a: { version: 3, link: LINK_A, accepts: 2 },
    forgotten: { accepts: 1 },
    half: { version: 2, accepts: 3 },
    zero: { version: 2, link: "A".repeat(43), accepts: 1 },
    odd: { version: 2, link: LINK_A, accepts: -1 },
    frac: { version: 2, link: LINK_A, accepts: 1.5 },
    none: { accepts: 0 },
  });
  expect(Object.fromEntries(read)).toStrictEqual({
    a: { version: 3, link: LINK_A, accepts: 2 },
    forgotten: { accepts: 1 },
    half: { accepts: 3 },
    zero: { accepts: 1 },
    odd: { version: 2, link: LINK_A },
    frac: { version: 2, link: LINK_A },
  });
  expect(readManifestMemory(JSON.parse(JSON.stringify(storedManifestMemory(read))))).toStrictEqual(read);
  // Merge (stored first): more acceptances win, whatever the versions; then the higher version; then the stored one.
  const stored: ManifestMemory = new Map([
    ["accepted-here", { version: 9, link: LINK_A }],
    ["accepted-there", { version: 2, link: LINK_A, accepts: 2 }],
    ["forgot-here", { version: 5, link: LINK_A }],
    ["forgot-there", { accepts: 1 }],
    ["same-accepts", { version: 3, link: LINK_A, accepts: 1 }],
    ["same-all", { version: 3, link: LINK_A, accepts: 1 }],
    ["after-forget", { accepts: 1 }],
  ]);
  const worker: ManifestMemory = new Map([
    ["accepted-here", { version: 2, link: LINK_B, accepts: 1 }],
    ["accepted-there", { version: 9, link: LINK_B, accepts: 1 }],
    ["forgot-here", { accepts: 1 }],
    ["forgot-there", { version: 5, link: LINK_B }],
    ["same-accepts", { version: 4, link: LINK_B, accepts: 1 }],
    ["same-all", { version: 3, link: LINK_B, accepts: 1 }],
    ["after-forget", { version: 1, link: LINK_B, accepts: 1 }],
  ]);
  expect(Object.fromEntries(mergeManifestMemory(stored, worker))).toStrictEqual({
    "accepted-here": { version: 2, link: LINK_B, accepts: 1 }, // the acceptance lowers the stored version
    "accepted-there": { version: 2, link: LINK_A, accepts: 2 }, // a copy from before the acceptance can't bring 9 back
    "forgot-here": { accepts: 1 },
    "forgot-there": { accepts: 1 },
    "same-accepts": { version: 4, link: LINK_B, accepts: 1 },
    "same-all": { version: 3, link: LINK_A, accepts: 1 },
    "after-forget": { version: 1, link: LINK_B, accepts: 1 },
  });
});

test("ROUND 2 (S7) standing warnings: only a warning with a cause and the row it was judged on is read from the offline copy; the row's stamp moves with any write into the vault", () => {
  const ok = { status: "mismatch", cause: "accept", stamp: "s" };
  expect([...readStanding({ a: ok, b: { status: "rollback", cause: "unopenable", stamp: "t" }, c: { status: "rollback", cause: "review", stamp: "" } })]).toStrictEqual([
    ["a", ok],
    ["b", { status: "rollback", cause: "unopenable", stamp: "t" }],
    ["c", { status: "rollback", cause: "review", stamp: "" }],
  ]);
  // Never an "ok" (or anything else) from the copy.
  for (const bad of [
    { status: "ok", cause: "accept", stamp: "s" },
    { status: "none", stamp: "s" },
    { status: "mismatch", cause: "x", stamp: "s" },
    { status: "mismatch", cause: "accept" },
    { status: "unchecked", cause: "accept", stamp: "s" },
    null,
    "mismatch",
    3,
  ])
    expect(readStanding({ a: bad }).size, JSON.stringify(bad)).toBe(0);
  for (const none of [null, undefined, [], "x", 7]) expect(readStanding(none).size).toBe(0);
  const row = vaultRow({ manifest: "m", manifest_seq: 3, manifest_prev: LINK_A });
  expect(rowStampOf(row)).toBe(rowStampOf(vaultRow({ manifest: "m", manifest_seq: 3, manifest_prev: LINK_A })));
  for (const other of [{ seq: 8 }, { manifest: "n" }, { manifest_seq: 4 }, { manifest_prev: LINK_B }, { key_epoch: 9 }, { wrapped_key: "w2" }])
    expect(rowStampOf(vaultRow({ manifest: "m", manifest_seq: 3, manifest_prev: LINK_A, ...other })), JSON.stringify(other)).not.toBe(rowStampOf(row));
});

test("the manifest log: pages are followed while the server says more, at most five requests; no log, or one that doesn't end, doesn't connect; a failure is passed on; only well-typed entries are kept", async () => {
  const asked: number[] = [];
  const e = (seq: number) => ({ seq, prev: `p${seq}`, digest: `d${seq}` });
  const pages = (list: unknown[]) => async (after: number) => {
    asked.push(after);
    return list.shift();
  };
  expect(await collectLog(3, pages([{ entries: [e(4), e(5)], more: false }]))).toStrictEqual([e(4), e(5)]);
  expect(asked).toStrictEqual([3]);
  asked.length = 0;
  expect(
    await collectLog(
      3,
      pages([
        { entries: [e(4)], more: true },
        { entries: [e(5), e(6)], more: true },
        { entries: [e(7)], more: false },
      ]),
    ),
  ).toStrictEqual([e(4), e(5), e(6), e(7)]);
  expect(asked, "each page from the highest entry of the one before").toStrictEqual([3, 4, 6]);
  // ROUND 2 (S9): what isn't an entry is left out (never fatal, never passed on); the entries stay exactly as sent.
  const extra = { ...e(5), more: "fields", stay: true };
  asked.length = 0;
  expect(
    await collectLog(
      3,
      pages([
        { entries: [null, 7, "x", [], {}, { seq: "4", prev: "p", digest: "d" }, e(4), { seq: 9 }, extra, { seq: 0, prev: "p", digest: "d" }], more: true },
        { entries: [{ seq: 6, prev: 1, digest: "d" }, e(6), "rubbish"], more: false },
      ]),
    ),
  ).toStrictEqual([e(4), extra, e(6)]);
  expect(asked, "the next page goes on from the highest real entry").toStrictEqual([3, 5]);
  // A 404 or 400 (the caller's null), an answer that isn't a log: it doesn't connect.
  for (const none of [null, undefined, {}, { entries: "x" }, []]) expect(await collectLog(3, async () => none)).toBe(null);
  // "More" forever: five requests, then it doesn't connect.
  let n = 3;
  asked.length = 0;
  expect(
    await collectLog(3, async (after) => {
      asked.push(after);
      return { entries: [e(++n)], more: true };
    }),
  ).toBe(null);
  expect(asked).toHaveLength(LOG_REQUESTS);
  expect(LOG_REQUESTS).toBe(5);
  // "More" that leads nowhere (nothing higher, nothing at all, or only rubbish): not asked again.
  expect(await collectLog(3, async () => ({ entries: [e(3)], more: true }))).toBe(null);
  expect(await collectLog(3, async () => ({ entries: [], more: true }))).toBe(null);
  expect(await collectLog(3, async () => ({ entries: [{ seq: 9 }], more: true }))).toBe(null);
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
  // ROUND 2 (S2): never over a row that doesn't open: the vault would be a mismatch for every member from then on.
  expect(mayStart({ ...ok, unopenable: true }), "an item of the vault doesn't open").toBe(false);
  expect(mayStart({ ...ok, unopenable: false })).toBe(true);
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
  // ROUND 2 (S5): the server's rule is strict, `deleted_at < server_time - trash_days days` (the edge doesn't count
  // yet: one second later it does), the same in every client.
  expect(dueTrash(rows, V.vaultId, served, seen, now).map((r) => r.id)).toStrictEqual(["due", "old"]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now + 1, trashDays: 30 }, seen, now + 1).map((r) => r.id)).toStrictEqual(["edge", "due", "old", "justSeen"]);
  // ROUND 2 (S5): the floor. Whatever period the server names, nothing goes before this browser watched it in the
  // trash for max(trash_days, 7) days.
  expect(TRASH_FLOOR_DAYS).toBe(7);
  const short = { serverTime: now, trashDays: 1 };
  expect(dueTrash(rows, V.vaultId, short, new Map([["due", now - 7 * day + 1]]), now), "watched a second less than a week").toStrictEqual([]);
  expect(dueTrash(rows, V.vaultId, short, new Map([["due", now - 2 * day]]), now), "two days, with a one-day setting").toStrictEqual([]);
  expect(
    dueTrash(rows, V.vaultId, short, new Map([["due", now - 7 * day]]), now).map((r) => r.id),
    "a week",
  ).toStrictEqual(["due"]);
  expect(dueTrash(rows, V.vaultId, { serverTime: now, trashDays: 7 }, new Map([["due", now - 7 * day]]), now).map((r) => r.id)).toStrictEqual(["due"]);
  // A longer setting still asks for the whole period.
  expect(dueTrash(rows, V.vaultId, served, new Map([["due", now - 29 * day]]), now)).toStrictEqual([]);
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
  // ROUND 2: the texts every client shares.
  expect(MANIFEST_READER_TEXT).toBe("Someone who can edit this vault can review it.");
  expect([MANIFEST_ACCEPT_ACTION, MANIFEST_ACCEPT_TITLE]).toStrictEqual(["Use the server's copy", "Use the server's copy?"]);
  expect(MANIFEST_ACCEPT_BODY).toBe(
    "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup.",
  );
  expect(MANIFEST_ITEM_TEXT).toBe("An item in this vault can't be opened. Delete it to keep using the vault.");
  expect(MANIFEST_ITEM_READER_TEXT).toBe("An item in this vault can't be opened. Someone who can edit this vault can delete it.");
  expect(MANIFEST_UNCHECKED_TEXT).toBe("PassAuth couldn't check this vault with your server yet. Try again in a moment.");
  expect(MEMORY_UNREADABLE_TEXT).toBe("PassAuth can't read this device's record of your vaults.");
  expect(MEMORY_RESET_ACTION).toBe("Reset on this device");
  expect(MEMORY_RESET_BODY).toBe("PassAuth will trust what your server shows now and start a new record on this device.");
  const vaults = [
    { id: "b", name: "Team", role: "write" },
    { id: "a", name: "Personal", role: "owner" },
    { id: "c", name: "Fine", role: "owner" },
    { id: "d", name: "Waiting", role: "owner" },
    { id: "e", name: "Read only", role: "read" },
    { id: "f", name: "Read item", role: "read" },
    { id: "g", name: "Item", role: "admin" },
    { id: "h", name: "Read accept", role: "read" },
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
      ["e", "mismatch"],
      ["f", "mismatch"],
      ["g", "mismatch"],
      ["h", "rollback"],
    ]),
    new Map([
      ["a", { cause: "accept" as const }],
      ["b", { cause: "review" as const }],
      ["e", { cause: "review" as const }],
      ["f", { cause: "unopenable" as const }],
      ["g", { cause: "unopenable" as const }],
      ["h", { cause: "accept" as const }],
    ]),
  );
  // ROUND 2 (S1, S2): "Use the server's copy" whenever the served copy checks out on its own, whatever the role;
  // else where to go (writers) or who can (readers); an item that can't be opened says so, and is never "accepted".
  expect(n?.vaults).toStrictEqual([
    { id: "b", name: "Team", text: MANIFEST_WARNING_TEXT, hint: MANIFEST_REVIEW_TEXT, open: true },
    { id: "a", name: "Personal", text: MANIFEST_WARNING_TEXT, accept: true },
    { id: "e", name: "Read only", text: MANIFEST_WARNING_TEXT, hint: MANIFEST_READER_TEXT },
    { id: "f", name: "Read item", text: MANIFEST_ITEM_READER_TEXT },
    { id: "g", name: "Item", text: MANIFEST_ITEM_TEXT, hint: MANIFEST_ITEM_WHERE_TEXT, open: true },
    { id: "h", name: "Read accept", text: MANIFEST_WARNING_TEXT, accept: true },
  ]);
  expect(n?.confirm).toStrictEqual({ action: MANIFEST_ACCEPT_ACTION, title: MANIFEST_ACCEPT_TITLE, body: MANIFEST_ACCEPT_BODY });
  // A cause nobody recorded is the careful one: reviewed elsewhere, nothing offered here.
  expect(warningOf(undefined, true)).toStrictEqual({ text: MANIFEST_WARNING_TEXT, hint: MANIFEST_REVIEW_TEXT, open: true });
  expect(manifestNotice([{ id: "a", name: "P" }], new Map([["a", "mismatch"]]))?.vaults[0]).toStrictEqual({ id: "a", name: "P", text: MANIFEST_WARNING_TEXT, hint: MANIFEST_READER_TEXT });
});
