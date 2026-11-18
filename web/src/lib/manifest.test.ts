/**
 * Vault manifests, the rules without network (`manifest.ts`, with the real core): the shared golden vectors, every
 * verdict, the chain of links (a manifest names the one it replaces; the device remembers version and link), the
 * entries writes carry, device memory, when a first manifest starts, a baseline's version and the trash that is due.
 */
import { beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/passauth_core";
import { ApiError } from "./api";
import { afterWrite, applyOwnManifest, applyOwnWrite, knownSeq, mergeSync, type Snapshot } from "./delta";
import {
  CLOCK_SLACK,
  MANIFESTS_PREFIX,
  ManifestMemory,
  TRASH_FLOOR_DAYS,
  TRASH_SEEN_PREFIX,
  TrashSeen,
  ZERO_LINK,
  acceptVault,
  acceptable,
  asRemembered,
  linkStored,
  manifestsAsideKey,
  manifestsFailedKey,
  VIEW_UNCHECKED,
  baselineSeq,
  checkApplies,
  checkView,
  dueTrash,
  isLink,
  isTrashedRow,
  manifestQuery,
  manifestRaced,
  manifestRow,
  manifestSeq,
  manifestsKey,
  mayPurge,
  mayStart,
  nextEntry,
  readManifestMemory,
  rowLink,
  startEntry,
  trashSeenKey,
  unresolved,
  verifyVault,
  wireEntry,
  withQuery,
  type ManifestEntry,
  type Remembered,
} from "./manifest";
import { isTrustMemoryKey, type KeyValueStore } from "./signing";
import { allVectors, loadCore, unb64 } from "./test-core";
import { isSyncVaultRow, type SyncItemRow, type SyncResponse, type SyncVaultRow } from "./types";

interface Row {
  manifest_seq: number;
  manifest_prev: string | null;
  manifest: string | null;
  link: string | null;
}
interface Vectors {
  accountId: string;
  sessionBytes: string;
  vaultId: string;
  keyEpoch: number;
  wrappedKey: string;
  rotated: { keyEpoch: number; wrappedKey: string };
  version: number;
  terms: { id: string; trashed: boolean; dataSha256: string }[];
  items: Record<string, SyncItemRow[]>;
  malformed: { items: unknown[] }[];
  manifests: Record<string, Row>;
  checks: { name: string; manifest: string; key: "main" | "rotated"; keyEpoch: number; remembered: Remembered | null; log: unknown[] | null; items: string; expected: Record<string, unknown> }[];
  writes: { name: string; removed: unknown[]; added: unknown[]; after: SyncItemRow[]; expected: { seq: number; prev: string } }[];
  accepts: { name: string; manifest: string; key: "main" | "rotated"; keyEpoch: number; items: string; expected: Record<string, unknown> }[];
  badMemories: { version: number; link: string }[];
  starts: { name: string; key: "main" | "rotated"; keyEpoch: number; version: number; prev: string | null; items: string; remembered: Remembered | null; expected: { seq: number; prev: string } }[];
}

let v: Vectors;
let key: core.VaultKey;
let rotated: core.VaultKey;
const keyOf = (name: "main" | "rotated") => (name === "rotated" ? rotated : key);
const ZERO = "A".repeat(43);
/** The vault row of a named manifest of the vectors. */
const row = (name = "current", over: Partial<SyncVaultRow> = {}): SyncVaultRow => {
  const m = v.manifests[name];
  return { id: v.vaultId, meta: "m", role: "owner", wrapped_key: v.wrappedKey, key_kind: "account", key_epoch: v.keyEpoch, seq: 9, manifest: m.manifest, manifest_seq: m.manifest_seq, manifest_prev: m.manifest_prev, manifest_ok: true, ...over };
};
const mem = (name: string): Remembered => ({ version: v.manifests[name].manifest_seq, link: v.manifests[name].link! });
const rowOf = (m: ManifestEntry, over: Partial<SyncVaultRow> = {}) => row("current", { manifest: m.sealed, manifest_seq: m.seq, manifest_prev: m.prev, ...over });

beforeAll(async () => {
  await loadCore();
  v = (await allVectors()).vaultManifest as Vectors;
  const account = core.accountFromSessionBytes(v.accountId, unb64(v.sessionBytes));
  key = account.openVaultKey(v.vaultId, v.wrappedKey, "account", v.keyEpoch, false);
  rotated = account.openVaultKey(v.vaultId, v.rotated.wrappedKey, "account", v.rotated.keyEpoch, false);
});

const mapStore = () => {
  const m = new Map<string, string>();
  const store: KeyValueStore = { get: (k) => m.get(k) ?? null, set: (k, val) => void (val === null ? m.delete(k) : m.set(k, val)) };
  return { m, store };
};

describe("golden vectors (vaultManifest)", () => {
  it("every named manifest has the link the vectors list", () => {
    let n = 0;
    for (const [name, m] of Object.entries(v.manifests)) {
      if (m.link === null) continue;
      n++;
      expect(core.manifestLink(m.manifest_seq, m.manifest_prev!, m.manifest!), name).toBe(m.link);
      expect(rowLink(m), name).toBe(m.link);
    }
    expect(n).toBeGreaterThan(8);
  });

  it("every check gives the expected verdict, counts, version and link to remember", () => {
    expect(v.checks.length).toBeGreaterThan(40);
    for (const c of v.checks) {
      const m = v.manifests[c.manifest];
      const got = keyOf(c.key).manifestVerify(v.vaultId, c.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, c.remembered?.version, c.remembered?.link, c.log, v.items[c.items]);
      expect(got, c.name).toEqual(c.expected);
    }
  });

  it("every check with a log gets it as the vectors hold it (rubbish included): rubbish is skipped, never fatal", () => {
    const rubbish = v.checks.filter((c) => c.log?.some((e) => e === null || typeof e !== "object" || Array.isArray(e)));
    expect(rubbish.length).toBeGreaterThanOrEqual(2);
    expect(rubbish.map((c) => c.expected.status).sort()).toEqual(expect.arrayContaining(["mismatch", "ok"]));
    for (const c of rubbish) {
      // Through this app's own call the entries reach the core untouched as well.
      const got = verifyVault(keyOf(c.key), { id: v.vaultId, key_epoch: c.keyEpoch, ...v.manifests[c.manifest] }, c.remembered ?? undefined, v.items[c.items], c.log);
      expect(got.status, c.name).toBe(c.expected.status);
    }
  });

  it("every acceptance check (nothing remembered) gives the expected result as a whole", () => {
    expect(v.accepts.length).toBeGreaterThan(12);
    for (const a of v.accepts) {
      const m = v.manifests[a.manifest];
      const got = keyOf(a.key).manifestAccept(v.vaultId, a.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, v.items[a.items]);
      expect(got, a.name).toEqual(a.expected);
      // This app's call: "ok" with the head's version and link, "none", or not acceptable. Summary rows are never
      // counted by a hash the server sent (the web vault asks for whole rows).
      const mine = acceptVault(keyOf(a.key), { id: v.vaultId, key_epoch: a.keyEpoch, ...m }, v.items[a.items]);
      const summary = v.items[a.items].some((r) => typeof r.data !== "string");
      if (a.expected.status === "ok" && !summary) expect(mine, a.name).toEqual({ status: "ok", version: a.expected.version, link: a.expected.link });
      else if (a.expected.status === "none" && m.manifest_seq === 0) expect(mine, a.name).toEqual({ status: "none" });
      else expect(mine, a.name).toEqual({ status: "mismatch" });
      expect(acceptable(mine), a.name).toBe(mine.status !== "mismatch");
    }
  });

  it("every bad memory is refused by the core, and is nothing this app would ever store", () => {
    expect(v.badMemories.length).toBeGreaterThan(3);
    const m = v.manifests.current;
    for (const bad of v.badMemories) {
      expect(() => key.manifestVerify(v.vaultId, v.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, bad.version, bad.link, null, v.items.full), JSON.stringify(bad)).toThrow();
      expect(asRemembered(bad), JSON.stringify(bad)).toBeUndefined();
      // Through this app's call a throw is a mismatch, never "ok".
      expect(verifyVault(key, row(), bad, v.items.full).status, JSON.stringify(bad)).toBe("mismatch");
    }
    expect(asRemembered({ version: 2, link: ZERO_LINK })).toBeUndefined();
  });

  it("every malformed item set is refused by the check and by a new manifest", () => {
    expect(v.malformed.length).toBeGreaterThan(2);
    const m = v.manifests.current;
    for (const bad of v.malformed) {
      expect(() => key.manifestVerify(v.vaultId, v.keyEpoch, m.manifest_seq, m.manifest_prev, m.manifest, null, null, null, bad.items), JSON.stringify(bad)).toThrow();
      expect(() => key.manifestStart(v.vaultId, v.keyEpoch, 1, null, bad.items), JSON.stringify(bad)).toThrow();
      // And through this app's own call: a mismatch, nothing remembered.
      expect(verifyVault(key, row(), undefined, bad.items as SyncItemRow[]), JSON.stringify(bad)).toEqual({ status: "mismatch", version: 0, link: null });
    }
  });

  it("every write names the current manifest, is one version up, and the vault after it checks out with its link", () => {
    expect(v.writes.length).toBeGreaterThan(4);
    const cur = v.manifests.current;
    for (const w of v.writes) {
      const next = key.manifestNext(v.vaultId, v.keyEpoch, cur.manifest_seq, cur.manifest_prev!, cur.manifest!, w.removed, w.added) as { seq: number; prev: string; sealed: string; link: string };
      expect(next.seq, w.name).toBe(w.expected.seq);
      expect(next.prev, w.name).toBe(w.expected.prev);
      expect(next.prev, w.name).toBe(cur.link);
      const check = key.manifestVerify(v.vaultId, v.keyEpoch, next.seq, next.prev, next.sealed, cur.manifest_seq, cur.link, null, w.after) as { status: string; link: string };
      expect(check, w.name).toMatchObject({ status: "ok", version: next.seq, link: next.link });
    }
  });

  it("every start gives the listed version and predecessor and checks out for the device that remembers", () => {
    expect(v.starts.length).toBeGreaterThan(3);
    for (const st of v.starts) {
      const m = startEntry(keyOf(st.key), v.vaultId, st.keyEpoch, st.version, st.prev, v.items[st.items].map(manifestRow));
      expect({ seq: m.seq, prev: m.prev }, st.name).toEqual(st.expected);
      expect(verifyVault(keyOf(st.key), rowOf(m, { key_epoch: st.keyEpoch }), st.remembered ?? undefined, v.items[st.items]), st.name).toEqual({ status: "ok", version: m.seq, link: m.link });
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
  it("ok: what to remember is the row's version and link", () => {
    const cur = mem("current");
    expect(verifyVault(key, row(), undefined, v.items.full)).toEqual({ status: "ok", ...cur });
    expect(verifyVault(key, row(), cur, v.items.full)).toEqual({ status: "ok", ...cur });
    expect(verifyVault(key, row(), mem("second"), v.items.full)).toEqual({ status: "ok", ...cur });
  });

  it("rollback: a lower version than remembered, or no manifest after one was seen; the remembered pair stays", () => {
    const fourth = mem("fourth");
    expect(verifyVault(key, row(), fourth, v.items.full)).toEqual({ status: "rollback", ...fourth });
    expect(verifyVault(key, row("none"), mem("second"), v.items.full)).toEqual({ status: "rollback", ...mem("second") });
  });

  it("none: no manifest and none seen", () => {
    expect(verifyVault(key, row("none"), undefined, v.items.full)).toEqual({ status: "none", version: 0, link: null });
    expect(verifyVault(key, row("none", { manifest: undefined, manifest_seq: undefined, manifest_prev: undefined }), undefined, [])).toEqual({ status: "none", version: 0, link: null });
  });

  it("the chain: another manifest at the remembered version is a mismatch (a fork), whatever its items say", () => {
    // The device saw `current` (version 3); the server shows another valid version 3 built on the same version 2.
    expect(verifyVault(key, row("forkThird"), undefined, v.items.full).status).toBe("ok");
    expect(verifyVault(key, row("forkThird"), mem("current"), v.items.full)).toEqual({ status: "mismatch", ...mem("current") });
    expect(verifyVault(key, row(), mem("forkThird"), v.items.full)).toEqual({ status: "mismatch", ...mem("forkThird") });
  });

  it("the chain: a manifest further ahead needs the log; one that doesn't lead back to the remembered one is a mismatch", () => {
    const first = mem("first");
    const logOf = (...names: string[]) => names.map((n) => ({ seq: v.manifests[n].manifest_seq, prev: v.manifests[n].manifest_prev, digest: digestOf(n) }));
    const digestOf = (n: string) => v.checks.flatMap((c) => (c.log ?? []) as { seq: number; prev: string; digest: string }[]).find((e) => e.seq === v.manifests[n].manifest_seq && e.prev === v.manifests[n].manifest_prev)!.digest;
    // One step ahead needs nothing.
    expect(verifyVault(key, row(), mem("second"), v.items.full).status).toBe("ok");
    // Two steps: not a verdict yet, and nothing new to remember.
    expect(verifyVault(key, row(), first, v.items.full)).toEqual({ status: "need_log", ...first });
    // With the vault's log it is the row's manifest that is remembered.
    expect(verifyVault(key, row(), first, v.items.full, logOf("second", "current"))).toEqual({ status: "ok", ...mem("current") });
    // An empty log, or the other history's, doesn't connect; a second "need_log" is never returned once a log was given.
    expect(verifyVault(key, row(), first, v.items.full, [])).toEqual({ status: "mismatch", ...first });
    // The fork joined one version later: the device that saw `current` is on another history. One version above the
    // remembered one with another predecessor is a mismatch at once (round 2: no log is asked for).
    expect(verifyVault(key, row("forkFourth"), mem("current"), v.items.full)).toEqual({ status: "mismatch", ...mem("current") });
    expect(verifyVault(key, row("forkFourth"), mem("current"), v.items.full, logOf("forkThird", "forkFourth"))).toEqual({ status: "mismatch", ...mem("current") });
    // Two versions later: the log is needed, and doesn't connect.
    expect(verifyVault(key, row("forkFifth"), mem("current"), v.items.full).status).toBe("need_log");
    // Garbage in a log is never trusted: it is a mismatch at worst, never a crash.
    expect(verifyVault(key, row(), first, v.items.full, [null, 5, { seq: "2" }, ...logOf("second", "current"), { seq: 2, prev: "x", digest: "y" }]).status).toMatch(/^(ok|mismatch)$/);
  });

  it("the chain crosses a key replacement and a baseline by links alone", () => {
    expect(verifyVault(rotated, row("rotated", { key_epoch: v.rotated.keyEpoch }), mem("fifth"), v.items.rotated)).toEqual({ status: "ok", ...mem("rotated") });
    const named = (name: string) => v.checks.find((c) => c.name === name)!.remembered!;
    const onIt = named("a baseline, a device on the history it replaced");
    expect(verifyVault(key, row("baseline"), onIt, v.items.full)).toEqual({ status: "ok", ...mem("baseline") });
    // A device on the other history keeps its warning after someone else's baseline: its log never connects.
    const other = v.checks.find((c) => c.name === "a baseline, a device on the other history")!;
    expect(verifyVault(key, row("baseline"), other.remembered!, v.items.full)).toEqual({ status: "mismatch", ...other.remembered! });
    const further = v.checks.find((c) => c.name === "a baseline, a device further back on the other history, no log yet")!;
    expect(verifyVault(key, row("baseline"), further.remembered!, v.items.full).status).toBe("need_log");
    const withLog = v.checks.find((c) => c.name === "a baseline, a device further back on the other history")!;
    expect(verifyVault(key, row("baseline"), withLog.remembered!, v.items.full, withLog.log)).toEqual({ status: "mismatch", ...withLog.remembered! });
    // Its way out: the baseline matches the served items, so it can be accepted on that device alone.
    expect(acceptVault(key, row("baseline"), v.items.full)).toEqual({ status: "ok", ...mem("baseline") });
  });

  it("mismatch: an item changed, missing, added, or moved in or out of the trash", () => {
    const full = v.items.full;
    const older = full.map((r, i) => (i === 0 ? { ...r, data: `${r.data}x` } : r));
    const missing = full.slice(1);
    const extra = [...full, { ...full[0], id: "00000000-0000-4000-8000-0000000001ff" }];
    const restored = full.map((r) => ({ ...r, deleted_at: null }));
    for (const rows of [older, missing, extra, restored]) expect(verifyVault(key, row(), undefined, rows)).toEqual({ status: "mismatch", version: 0, link: null });
    // What was remembered stays as it was.
    expect(verifyVault(key, row(), mem("current"), missing)).toEqual({ status: "mismatch", ...mem("current") });
  });

  it("mismatch: a manifest that doesn't open for this vault, epoch, version and predecessor, or none where the row names a version", () => {
    for (const name of ["relabelled", "otherPrev", "noPrev", "noText", "otherEpoch", "otherVault", "lyingVersion", "garbage"]) expect(verifyVault(key, row(name), undefined, v.items.full).status, name).toBe("mismatch");
    expect(verifyVault(key, row("current", { key_epoch: v.keyEpoch + 1 }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row("current", { manifest_prev: ZERO }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row("current", { manifest_prev: 7 as unknown as string }), undefined, v.items.full).status).toBe("mismatch");
  });

  it("mismatch for anything the core refuses: an id listed twice, a version that isn't a whole number, a trash time that is no time", () => {
    expect(verifyVault(key, row(), undefined, [...v.items.full, v.items.full[0]]).status).toBe("mismatch");
    expect(verifyVault(key, row("current", { manifest_seq: -1 }), mem("fifth"), v.items.full)).toEqual({ status: "mismatch", ...mem("fifth") });
    expect(verifyVault(key, row("current", { manifest_seq: 1.5 }), undefined, v.items.full).status).toBe("mismatch");
    expect(verifyVault(key, row("current", { manifest_seq: "3" as unknown as number }), undefined, v.items.full).status).toBe("mismatch");
    // `deleted_at` 0 (or anything else that is no time) on a row the manifest counts as trashed: never "ok".
    const trashed = v.items.full.find((r) => r.deleted_at !== null)!;
    for (const at of [0, -5, 1.5, "7", true]) {
      const rows = v.items.full.map((r) => (r === trashed ? { ...r, deleted_at: at as number } : r));
      expect(verifyVault(key, row(), undefined, rows).status, String(at)).toBe("mismatch");
    }
  });

  it("the web vault never counts a row by a hash the server sent: without its data the vault is incomplete", () => {
    const [first, ...rest] = v.items.full;
    const bare = { id: first.id, deleted_at: first.deleted_at } as unknown as SyncItemRow;
    expect(verifyVault(key, row(), undefined, [bare, ...rest]).status).toBe("incomplete");
    // The correct hash next to it changes nothing here (review 4: a live item hidden behind its hash).
    const hashed = { ...bare, data_sha256: core.manifestDataHash(first.data) } as unknown as SyncItemRow;
    expect(verifyVault(key, row(), undefined, [hashed, ...rest]).status).toBe("incomplete");
    expect(manifestRow(hashed)).toEqual({ id: first.id, deleted_at: first.deleted_at });
    // Nor any other field a server could add to a row.
    expect(manifestRow({ ...first, served_sha256: "x", trashed: true } as unknown as SyncItemRow)).toEqual({ id: first.id, deleted_at: first.deleted_at, data: first.data });
  });

  it("only rollback, mismatch and incomplete hold a vault's writes back", () => {
    expect(["none", "ok", "rollback", "mismatch", "incomplete", undefined].map((s) => unresolved(s as never))).toEqual([false, false, true, true, true, false]);
  });
});

describe("which vaults are checked", () => {
  it("with the feature, or a manifest on the row, or one remembered: a server can't switch the check off by not listing it", () => {
    const none = { manifest_seq: 0, manifest: null };
    expect(checkApplies(true, none, undefined)).toBe(true);
    expect(checkApplies(false, none, undefined)).toBe(false);
    expect(checkApplies(false, { manifest_seq: 2, manifest: "x" }, undefined)).toBe(true);
    expect(checkApplies(false, { manifest_seq: 0, manifest: "x" }, undefined)).toBe(true);
    expect(checkApplies(false, none, mem("fourth"))).toBe(true);
    // And the remembered manifest then reads as a rollback.
    expect(verifyVault(key, row("none"), mem("fourth"), v.items.full).status).toBe("rollback");
  });
});

describe("the entries writes carry", () => {
  const full = () => v.items.full;
  const after = (rows: SyncItemRow[], entry: ManifestEntry | null) => verifyVault(key, rowOf(entry!), mem("current"), rows);

  it("nothing for a vault without a manifest", () => {
    expect(nextEntry(key, row("none"), [], [{ id: "x", deleted_at: null, data: "d" }])).toBeNull();
    expect(nextEntry(key, row("none", { manifest: undefined, manifest_seq: undefined }), [], [])).toBeNull();
    expect(manifestQuery(null)).toEqual([]);
    expect(withQuery("/items/x", [])).toBe("/items/x");
    expect(rowLink(row("none"))).toBeNull();
  });

  it("create, edit, trash, restore and delete for good: one version up, naming the row's manifest, and the vault after the write checks out", () => {
    const [a, b, c] = full();
    const created: SyncItemRow = { ...a, id: "00000000-0000-4000-8000-0000000001aa", data: "new-data" };
    const e1 = nextEntry(key, row(), [], [manifestRow(created)])!;
    expect(e1).toMatchObject({ vault_id: v.vaultId, seq: v.version + 1, prev: v.manifests.current.link });
    expect(isLink(e1.link)).toBe(true);
    expect(after([...full(), created], e1)).toEqual({ status: "ok", version: e1.seq, link: e1.link });
    // The link is the row's link: what the next write names, and what a later answer at that version must show.
    expect(rowLink(rowOf(e1))).toBe(e1.link);
    expect(nextEntry(key, rowOf(e1), [], [{ id: "00000000-0000-4000-8000-0000000001ac", deleted_at: null, data: "d" }])!.prev).toBe(e1.link);

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

  it("a request carries seq, prev and sealed (never the link); a write without a body has all three in its query", () => {
    const entry = nextEntry(key, row(), [], [{ id: "00000000-0000-4000-8000-0000000001ab", deleted_at: null, data: "d" }])!;
    expect(wireEntry(entry)).toEqual({ vault_id: v.vaultId, seq: entry.seq, prev: entry.prev, sealed: entry.sealed });
    expect(withQuery("/items/i", ["revision=4", ...manifestQuery(entry)])).toBe(`/items/i?revision=4&manifest_seq=${entry.seq}&manifest_prev=${entry.prev}&manifest=${entry.sealed}`);
    expect(entry.sealed).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("a whole manifest for a new key or a baseline names the row it replaces by its link", () => {
    const prev = rowLink(row())!;
    expect(prev).toBe(v.manifests.current.link);
    const m = startEntry(key, v.vaultId, v.keyEpoch + 1, 9, prev, full().map(manifestRow));
    expect(m).toMatchObject({ seq: 9, prev });
    expect(verifyVault(key, rowOf(m, { key_epoch: v.keyEpoch + 1 }), mem("current"), full())).toEqual({ status: "ok", version: 9, link: m.link });
    // Sealed for another epoch, version or predecessor it doesn't open.
    expect(verifyVault(key, rowOf(m), mem("current"), full()).status).toBe("mismatch");
    expect(verifyVault(key, rowOf(m, { manifest_seq: 10, key_epoch: v.keyEpoch + 1 }), mem("current"), full()).status).toBe("mismatch");
    expect(verifyVault(key, rowOf(m, { manifest_prev: ZERO, key_epoch: v.keyEpoch + 1 }), mem("current"), full()).status).toBe("mismatch");
    // A first manifest names none.
    expect(startEntry(key, v.vaultId, v.keyEpoch, 1, null, []).prev).toBe(ZERO);
    // A baseline is built on whatever the server shows, also a manifest this device can't open.
    expect(isLink(rowLink(row("garbage")))).toBe(true);
    expect(() => rowLink(row("noPrev"))).toThrow();
    expect(() => rowLink(row("noText"))).toThrow();
  });

  it("a row without a readable manifest, predecessor or key epoch is never built on", () => {
    expect(() => nextEntry(key, row("current", { manifest: null }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row("current", { key_epoch: undefined }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row("current", { manifest_prev: null }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row("current", { manifest_prev: "short" }), [], [])).toThrow("can't be changed");
    expect(() => nextEntry(key, row("relabelled"), [], [])).toThrow();
    expect(() => nextEntry(key, row("current", { manifest_seq: Number.MAX_SAFE_INTEGER }), [], [])).toThrow("can't be changed");
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
  const L = (c: string) => c.repeat(43);
  const stored = (m: Map<string, string>) => JSON.parse(m.get(manifestsKey(scope))!) as Record<string, unknown>;

  it("keeps version and link, is only ever raised, per vault, and survives a reload", () => {
    const { m, store } = mapStore();
    const memory = new ManifestMemory(store, scope);
    expect(memory.get("v1")).toBeUndefined();
    memory.raise("v1", 3, L("a"));
    memory.raise("v1", 2, L("b"));
    memory.raise("v2", 1, L("c"));
    memory.raise("v3", 0, L("d"));
    memory.raise("v3", 1.5, L("d"));
    memory.raise("v4", 2, null);
    memory.raise("v4", 2, "not a link");
    memory.flush();
    expect(stored(m)).toEqual({ v1: { version: 3, link: L("a") }, v2: { version: 1, link: L("c") } });
    const again = new ManifestMemory(store, scope);
    expect(again.get("v1")).toEqual({ version: 3, link: L("a") });
    expect(again.get("v3")).toBeUndefined();
    expect(again.get("v4")).toBeUndefined();
  });

  it("never replaces the link of a version it remembers", () => {
    const { m, store } = mapStore();
    const memory = new ManifestMemory(store, scope);
    memory.raise("v1", 3, L("a"));
    memory.raise("v1", 3, L("b"));
    memory.flush();
    expect(stored(m)).toEqual({ v1: { version: 3, link: L("a") } });
  });

  it("PoC 4 (rereview 7): at the same version the stored link stays, and the tab that held another one takes it (its next check says so)", () => {
    const { m, store } = mapStore();
    const tabA = new ManifestMemory(store, scope);
    const tabB = new ManifestMemory(store, scope);
    tabA.raise("v", 5, L("a"));
    tabA.flush();
    tabB.raise("v", 5, L("b"));
    tabB.flush();
    // The stored one is never written over at its version...
    expect(stored(m)).toEqual({ v: { version: 5, link: L("a") } });
    // ...and the tab that was on another history now holds the stored link: checking its copy against it fails.
    expect(tabB.get("v")).toEqual({ version: 5, link: L("a") });
    expect(tabA.refresh().size).toBe(0);
    expect(tabA.get("v")).toEqual({ version: 5, link: L("a") });
    // `refresh` names what changed under a tab.
    m.set(manifestsKey(scope), JSON.stringify({ v: { version: 5, link: L("z") }, w: { version: 1, link: L("w") } }));
    expect([...tabA.refresh()].sort()).toEqual(["v", "w"]);
    expect(tabA.get("v")).toEqual({ version: 5, link: L("z") });
  });

  it("an acceptance replaces the entry whatever it held (also downwards) and counts `accepts`; a stale tab can't bring the old one back", () => {
    const { m, store } = mapStore();
    const one = new ManifestMemory(store, scope);
    const stale = new ManifestMemory(store, scope);
    one.raise("v", 9, L("a"));
    one.flush();
    stale.refresh();
    expect(stale.get("v")).toEqual({ version: 9, link: L("a") });
    expect(one.replace("v", 4, L("b"))).toBe(true);
    expect(stored(m)).toEqual({ v: { version: 4, link: L("b"), accepts: 1 } });
    // The stale tab writes its whole map: the accepted entry stays, and the tab takes it over.
    stale.raise("other", 1, L("o"));
    stale.flush();
    expect(stored(m)).toEqual({ v: { version: 4, link: L("b"), accepts: 1 }, other: { version: 1, link: L("o") } });
    expect(stale.get("v")).toEqual({ version: 4, link: L("b") });
    // Ordinary use goes on from the accepted entry and keeps the count.
    stale.raise("v", 5, L("c"));
    stale.flush();
    expect(stored(m).v).toEqual({ version: 5, link: L("c"), accepts: 1 });
    // A second acceptance, made by a tab that hadn't seen the first: read, changed and written on top of what is stored.
    const third = new ManifestMemory(store, scope);
    m.set(manifestsKey(scope), JSON.stringify({ v: { version: 7, link: L("d"), accepts: 3 } }));
    expect(third.replace("v", 2, L("e"))).toBe(true);
    expect(stored(m).v).toEqual({ version: 2, link: L("e"), accepts: 4 });
    // Never anything that is no manifest's version and link.
    expect(third.replace("v", 0, L("e"))).toBe(false);
    expect(third.replace("v", 3, ZERO_LINK)).toBe(false);
    expect(stored(m).v).toEqual({ version: 2, link: L("e"), accepts: 4 });
  });

  it("forgetting (the server shows no manifest, accepted) keeps only the count: nothing remembered, and no older copy brings the version back", () => {
    const { m, store } = mapStore();
    const one = new ManifestMemory(store, scope);
    const stale = new ManifestMemory(store, scope);
    one.raise("v", 6, L("a"));
    one.flush();
    stale.refresh();
    expect(one.notChecked("v")).toBe(false);
    expect(one.forget("v")).toBe(true);
    // The entry says the memory was given up (T3: the vault shows "not checked" until it has a record again).
    expect(stored(m)).toEqual({ v: { accepts: 1, forgotten: true } });
    expect(one.get("v")).toBeUndefined();
    expect(one.notChecked("v")).toBe(true);
    expect([...readManifestMemory(store, scope)!]).toEqual([]);
    stale.raise("x", 1, L("x"));
    stale.flush();
    expect(stored(m).v).toEqual({ accepts: 1, forgotten: true });
    expect(stale.get("v")).toBeUndefined();
    // Another tab and a reload see the marker too.
    expect(stale.notChecked("v")).toBe(true);
    expect(new ManifestMemory(store, scope).notChecked("v")).toBe(true);
    // A first manifest later is remembered as usual, and the marker goes with it.
    one.raise("v", 1, L("n"));
    one.flush();
    expect(stored(m).v).toEqual({ version: 1, link: L("n"), accepts: 1 });
    expect(one.notChecked("v")).toBe(false);
    expect(new ManifestMemory(store, scope).get("v")).toEqual({ version: 1, link: L("n") });
    expect(new ManifestMemory(store, scope).notChecked("v")).toBe(false);
    stale.refresh();
    expect(stale.notChecked("v")).toBe(false);
  });

  it("the 'not checked' marker: only from a forget, never read off an entry that remembers a manifest, gone after an accepted record", () => {
    const { m, store } = mapStore();
    // A stored entry claiming both: the memory counts, the marker doesn't.
    m.set(manifestsKey(scope), JSON.stringify({ v: { version: 2, link: L("a"), accepts: 1, forgotten: true }, w: { accepts: 2, forgotten: "yes" }, x: { accepts: 1, forgotten: true } }));
    const mem = new ManifestMemory(store, scope);
    expect(mem.get("v")).toEqual({ version: 2, link: L("a") });
    expect(mem.notChecked("v")).toBe(false);
    expect(mem.notChecked("w")).toBe(false);
    expect(mem.notChecked("x")).toBe(true);
    expect(mem.notChecked("unknown")).toBe(false);
    expect(mem.replace("x", 3, L("b"))).toBe(true);
    expect(mem.notChecked("x")).toBe(false);
    expect(stored(m).x).toEqual({ version: 3, link: L("b"), accepts: 2 });
  });

  it("the all-zero link is never remembered (the core refuses it as a memory)", () => {
    const { m, store } = mapStore();
    const memory = new ManifestMemory(store, scope);
    memory.raise("v", 2, ZERO_LINK);
    memory.flush();
    expect(m.size).toBe(0);
    m.set(manifestsKey(scope), JSON.stringify({ v: { version: 2, link: ZERO_LINK } }));
    expect(new ManifestMemory(store, scope).get("v")).toBeUndefined();
    expect(isLink(ZERO_LINK)).toBe(true);
  });

  it("an unreadable record: acceptances write nothing; failed reads are counted across reloads; the reset moves it aside", () => {
    const { m, store } = mapStore();
    m.set(manifestsKey(scope), "{broken");
    const memory = new ManifestMemory(store, scope);
    expect(memory.replace("v", 2, L("a"))).toBe(false);
    expect(memory.forget("v")).toBe(false);
    expect(m.get(manifestsKey(scope))).toBe("{broken");
    expect(memory.noteRead(true)).toBe(1);
    expect(new ManifestMemory(store, scope).noteRead(true)).toBe(2);
    expect(memory.noteRead(true)).toBe(3);
    expect(isTrustMemoryKey(manifestsFailedKey(scope))).toBe(true);
    expect(isTrustMemoryKey(manifestsAsideKey(scope))).toBe(true);
    memory.reset();
    expect(memory.unreadable).toBe(false);
    expect(m.get(manifestsKey(scope))).toBeUndefined();
    expect(m.get(manifestsAsideKey(scope))).toBe("{broken");
    expect(m.get(manifestsFailedKey(scope))).toBeUndefined();
    expect(memory.noteRead(false)).toBe(0);
    memory.raise("v", 1, L("a"));
    memory.flush();
    expect(stored(m)).toEqual({ v: { version: 1, link: L("a") } });
    // A record that reads is never reset.
    memory.reset();
    expect(stored(m)).toEqual({ v: { version: 1, link: L("a") } });
    // It becomes readable again by another tab's doing: this one goes on.
    const other = new ManifestMemory(store, scope);
    m.set(manifestsKey(scope), "{broken");
    other.refresh();
    expect(other.unreadable).toBe(true);
    m.set(manifestsKey(scope), JSON.stringify({ v: { version: 2, link: L("b") } }));
    other.refresh();
    expect(other.unreadable).toBe(false);
    expect(other.get("v")).toEqual({ version: 2, link: L("b") });
  });

  it("merges with another tab's writes: the higher version wins with its link, nothing is dropped", () => {
    const { m, store } = mapStore();
    const one = new ManifestMemory(store, scope);
    const two = new ManifestMemory(store, scope);
    one.raise("v1", 5, L("a"));
    one.raise("gone", 2, L("g"));
    one.flush();
    two.raise("v1", 4, L("b"));
    two.raise("v2", 7, L("c"));
    two.flush();
    expect(stored(m)).toEqual({ v1: { version: 5, link: L("a") }, v2: { version: 7, link: L("c") }, gone: { version: 2, link: L("g") } });
    expect(two.get("v1")).toEqual({ version: 5, link: L("a") });
    one.refresh();
    expect(one.get("v2")).toEqual({ version: 7, link: L("c") });
  });

  it("an entry in the first format (a bare number), half a pair or a bad link is nothing remembered", () => {
    const { m, store } = mapStore();
    m.set(manifestsKey(scope), JSON.stringify({ a: 2, b: { version: 3 }, c: { link: L("a") }, d: { version: 3, link: "short" }, e: { version: 0, link: L("a") }, f: { version: 1.5, link: L("a") }, g: { version: 4, link: L("g") }, h: null }));
    expect([...readManifestMemory(store, scope)!]).toEqual([["g", { version: 4, link: L("g") }]]);
    const memory = new ManifestMemory(store, scope);
    expect(memory.unreadable).toBe(false);
    expect(memory.get("a")).toBeUndefined();
    expect(asRemembered(5)).toBeUndefined();
    expect(asRemembered({ version: 5, link: L("x") })).toEqual({ version: 5, link: L("x") });
  });

  it("a stored value that can't be read is not 'nothing remembered': it is never checked against and never written over", () => {
    const { m, store } = mapStore();
    for (const bad of ["{not json", "[]", "7", '"x"']) {
      m.set(manifestsKey(scope), bad);
      expect(readManifestMemory(store, scope)).toBeNull();
      const memory = new ManifestMemory(store, scope);
      expect(memory.unreadable).toBe(true);
      memory.raise("v1", 3, L("a"));
      memory.flush();
      expect(memory.get("v1")).toBeUndefined();
      expect(m.get(manifestsKey(scope))).toBe(bad);
    }
    // Another tab's value turning unreadable stops this one writing too.
    m.delete(manifestsKey(scope));
    const memory = new ManifestMemory(store, scope);
    memory.raise("v1", 3, L("a"));
    m.set(manifestsKey(scope), "{broken");
    memory.flush();
    expect(m.get(manifestsKey(scope))).toBe("{broken");
    expect(memory.unreadable).toBe(true);
  });

  it("writes nothing when nothing was raised, and is kept with the other device memory", () => {
    const { m, store } = mapStore();
    new ManifestMemory(store, scope).flush();
    expect(m.size).toBe(0);
    expect(isTrustMemoryKey(manifestsKey(scope))).toBe(true);
    expect(manifestsKey(scope).startsWith(MANIFESTS_PREFIX)).toBe(true);
    expect(isTrustMemoryKey(trashSeenKey(scope))).toBe(true);
    expect(trashSeenKey(scope).startsWith(TRASH_SEEN_PREFIX)).toBe(true);
    expect(isTrustMemoryKey("pa.server-features.https://vault.example.test")).toBe(true);
  });
});

describe("starting a first manifest", () => {
  const none = (over: Partial<SyncVaultRow> = {}) => row("none", { manifest_ok: true, ...over });

  it("only with the feature, the server's go-ahead, write access, no manifest and none ever seen", () => {
    expect(mayStart(true, none(), "none", undefined)).toBe(true);
    for (const role of ["write", "admin", "owner"] as const) expect(mayStart(true, none({ role }), "none", undefined)).toBe(true);
    expect(mayStart(false, none(), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: false }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: undefined }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ manifest_ok: 1 as unknown as boolean }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ role: "read" }), "none", undefined)).toBe(false);
    expect(mayStart(true, none(), "none", mem("second"))).toBe(false);
    expect(mayStart(true, none(), "rollback", mem("second"))).toBe(false);
    expect(mayStart(true, row(), "ok", undefined)).toBe(false);
    expect(mayStart(true, none({ seq: undefined }), "none", undefined)).toBe(false);
    expect(mayStart(true, none({ key_epoch: undefined }), "none", undefined)).toBe(false);
  });
});

describe("a new baseline", () => {
  it("is always exactly one above the row's version, whatever the device remembers (the server refuses anything else)", () => {
    expect(baselineSeq({ manifest_seq: 3 })).toBe(4);
    expect(baselineSeq({ manifest_seq: 9 })).toBe(10);
    expect(baselineSeq({ manifest_seq: 0 })).toBe(1);
    expect(baselineSeq({})).toBe(1);
    expect(manifestSeq({ manifest_seq: -2 })).toBe(0);
  });

  it("an answer names the manifest sent only by its link", () => {
    const L = "a".repeat(43);
    expect(linkStored({ link: L }, L)).toBe(true);
    expect(linkStored({ link: L }, "b".repeat(43))).toBe(false);
    expect(linkStored({ link: L }, undefined)).toBe(false);
    expect(linkStored({ link: L }, null)).toBe(false);
    expect(linkStored(null, L)).toBe(false);
  });
});

describe("old trash", () => {
  const item = (id: string, deleted_at: number | null): SyncItemRow => ({ id, vault_id: "v", item_key: "k", data: "d", revision: 1, deleted_at, created_at: 1, updated_at: 1 });
  const DAY = 86400;
  const T = 1_700_000_000;
  const rows = [item("live", null), item("old", T - 3 * DAY), item("edge", T - DAY), item("new", T - 100)];
  /** The device saw every row in the trash long ago. */
  const longAgo = () => 1;
  const ids = (list: SyncItemRow[]) => list.map((r) => r.id);

  it("is what has been in the trash longer than the server's retention, by the server's clock", () => {
    expect(ids(dueTrash(rows, T, 1, longAgo, T))).toEqual(["old"]);
    expect(ids(dueTrash(rows, T + 1, 1, longAgo, T))).toEqual(["old", "edge"]);
    expect(dueTrash(rows, T, 30, longAgo, T)).toEqual([]);
  });

  it("and only what this device itself has seen in the trash for that long, by its own clock", () => {
    // Never seen trashed here: nothing, whatever the server says (also right after this update).
    expect(dueTrash(rows, T, 1, () => undefined, T)).toEqual([]);
    // Seen for less than the retention, and never for less than seven days whatever retention the server names (S5).
    expect(TRASH_FLOOR_DAYS).toBe(7);
    expect(dueTrash(rows, T, 1, () => T - DAY, T)).toEqual([]);
    expect(dueTrash(rows, T, 1, () => T - 7 * DAY + 1, T)).toEqual([]);
    expect(ids(dueTrash(rows, T, 1, () => T - 7 * DAY, T))).toEqual(["old"]);
    expect(dueTrash(rows, T, 30, () => T - 30 * DAY + 1, T)).toEqual([]);
    expect(ids(dueTrash(rows, T, 1, (id) => (id === "old" ? undefined : 1), T + 5))).toEqual([]);
    // A server that claims a far future (or a `deleted_at` long past) deletes nothing the device hasn't watched.
    const fresh = [item("just", 5)];
    expect(dueTrash(fresh, Number.MAX_SAFE_INTEGER, 1, () => T - 10, T)).toEqual([]);
    expect(dueTrash(fresh, T, 1, () => T - 10, T)).toEqual([]);
  });

  it("and only while the server's clock and the device's agree within a day", () => {
    expect(ids(dueTrash(rows, T + CLOCK_SLACK, 1, longAgo, T))).toContain("old");
    expect(dueTrash(rows, T + CLOCK_SLACK + 1, 1, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T - CLOCK_SLACK - 1, 1, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, Number.MAX_SAFE_INTEGER, 1, longAgo, T)).toEqual([]);
  });

  it("is nothing when the server keeps the trash forever, didn't say, or sent numbers that can't be counted with", () => {
    expect(dueTrash(rows, T, 0, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T, undefined, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, undefined, 30, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T, -1, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T, 0.5, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T, Number.MAX_SAFE_INTEGER, longAgo, T)).toEqual([]);
    expect(dueTrash(rows, T + 0.5, 1, longAgo, T)).toEqual([]);
    expect(dueTrash([item("zero", 0), item("frac", 1.5), item("neg", -4)], T, 1, longAgo, T)).toEqual([]);
  });

  it("is deleted only in a vault that checked out, has a manifest and can be written", () => {
    expect(mayPurge(row(), "ok")).toBe(true);
    expect(mayPurge(row("current", { role: "read" }), "ok")).toBe(false);
    expect(mayPurge(row(), "mismatch")).toBe(false);
    expect(mayPurge(row(), "rollback")).toBe(false);
    expect(mayPurge(row("none"), "none")).toBe(false);
  });

  it("the device's record: first seen when first held in the trash, forgotten when live again or gone, kept across reloads", () => {
    const scope = "https://vault.example.test|acct";
    const { m, store } = mapStore();
    const seen = new TrashSeen(store, scope);
    seen.note([item("a", 5), item("b", null)], 1000);
    expect(seen.get("a")).toBe(1000);
    expect(seen.get("b")).toBeUndefined();
    seen.note([item("a", 5), item("b", 9)], 2000);
    expect([seen.get("a"), seen.get("b")]).toEqual([1000, 2000]);
    expect(JSON.parse(m.get(trashSeenKey(scope))!)).toEqual({ a: 1000, b: 2000 });
    const again = new TrashSeen(store, scope);
    expect(again.get("a")).toBe(1000);
    // Restored, then trashed again: the watch starts over. Gone: forgotten.
    again.note([item("a", null)], 3000);
    expect(again.get("a")).toBeUndefined();
    again.note([item("a", 7)], 4000);
    expect(again.get("a")).toBe(4000);
    again.note([], 5000);
    expect(m.has(trashSeenKey(scope))).toBe(false);
    // A device clock that went back never makes an item look watched for longer.
    again.note([item("a", 7)], 4000);
    again.note([item("a", 7)], 3000);
    expect(again.get("a")).toBe(3000);
    // Unreadable: nothing seen.
    m.set(trashSeenKey(scope), "{broken");
    expect(new TrashSeen(store, scope).get("a")).toBeUndefined();
  });

  it("in the trash is exactly: deleted_at is not null", () => {
    expect(isTrashedRow({ deleted_at: null })).toBe(false);
    expect(isTrashedRow({ deleted_at: undefined as unknown as null })).toBe(false);
    expect(isTrashedRow({ deleted_at: 5 })).toBe(true);
    expect(isTrashedRow({ deleted_at: 0 })).toBe(true);
  });
});

describe("a read-only view of someone else's vault (emergency access)", () => {
  type R = { id: string; deletedAt: number | null; data: string; fails?: boolean };
  const rows = (): R[] => v.items.full.map((r) => ({ id: r.id, deletedAt: r.deleted_at, data: r.data }));
  const vault = (name = "current") => ({ id: v.vaultId, keyEpoch: v.keyEpoch, manifest: v.manifests[name].manifest, manifestSeq: v.manifests[name].manifest_seq, manifestPrev: v.manifests[name].manifest_prev });
  const open = (r: R) => {
    if (r.fails) throw new Error("decrypt_failed");
    return r.id;
  };

  it("checks out against the manifest of the answer, with its predecessor link", () => {
    const view = checkView(key, vault(), rows(), 0, open);
    expect(view).toMatchObject({ warning: false, unchecked: false, failed: 0 });
    expect(view.opened).toHaveLength(rows().length);
    // Without the link the manifest doesn't open.
    expect(checkView(key, { ...vault(), manifestPrev: null }, rows(), 0, open).warning).toBe(true);
  });

  it("warns for an item changed or missing, a row the app couldn't read, and a row that doesn't open (a broken item key)", () => {
    expect(checkView(key, vault(), rows().slice(1), 0, open).warning).toBe(true);
    expect(checkView(key, vault(), rows().map((r, i) => (i ? r : { ...r, data: `${r.data}x` })), 0, open).warning).toBe(true);
    expect(checkView(key, vault(), rows(), 1, open).warning).toBe(true);
    const hidden = checkView(key, vault(), rows().map((r, i) => (i ? r : { ...r, fails: true })), 0, open);
    expect(hidden).toMatchObject({ warning: true, failed: 1 });
    expect(hidden.opened).toHaveLength(rows().length - 1);
    // A trashed item served as `deleted_at: 0` is no "live" item: the vault doesn't check out.
    const trashed = rows().find((r) => r.deletedAt !== null)!;
    expect(checkView(key, vault(), rows().map((r) => (r.id === trashed.id ? { ...r, deletedAt: 0 } : r)), 0, open).warning).toBe(true);
    expect(checkView(key, { ...vault(), manifestSeq: -1 }, rows(), 0, open).warning).toBe(true);
  });

  it("a row that decrypts but holds an item from a newer app is left out without a warning (T1b); together with a row that doesn't decrypt, the warning stays", () => {
    const openNewer = (r: R & { newer?: boolean }) => {
      if (r.newer) throw new Error("json: unknown variant `passport`, expected one of `text`, `hidden`, `boolean` at line 1 column 277");
      return open(r);
    };
    const newer = checkView(key, vault(), rows().map((r, i) => (i ? r : { ...r, newer: true })), 0, openNewer);
    expect(newer).toMatchObject({ warning: false, unchecked: false, failed: 1, newer: 1 });
    expect(newer.opened).toHaveLength(rows().length - 1);
    const both = checkView(key, vault(), rows().map((r, i) => (i === 0 ? { ...r, newer: true } : i === 1 ? { ...r, fails: true } : r)), 0, openNewer);
    expect(both).toMatchObject({ warning: true, failed: 2, newer: 1 });
    // The manifest still decides: a newer row whose data isn't what the record counts is a warning like any other.
    expect(checkView(key, vault(), rows().map((r, i) => (i ? r : { ...r, newer: true, data: `${r.data}x` })), 0, openNewer).warning).toBe(true);
  });

  it("a vault without a manifest is 'not checked', not 'fine'", () => {
    expect(checkView(key, vault("none"), rows(), 0, open)).toMatchObject({ warning: false, unchecked: true, failed: 0 });
    expect(VIEW_UNCHECKED).toContain("couldn't check");
  });
});

describe("delta sync carries the manifest", () => {
  const user = { id: "u", email: "u@example.com", name: "U", email_verified: true };
  const item = (id: string, data = "d"): SyncItemRow => ({ id, vault_id: "v1", item_key: "k", data, revision: 1, deleted_at: null, created_at: 1, updated_at: 1 });
  const vault = (over: Partial<SyncVaultRow> = {}): SyncVaultRow => ({ id: "v1", meta: "m", role: "owner", wrapped_key: "w", key_kind: "account", key_epoch: 0, seq: 4, manifest: "aaa", manifest_seq: 2, manifest_prev: "p-aaa", manifest_ok: true, ...over });
  const answer = (over: Partial<SyncResponse> = {}): SyncResponse => ({ revision: 1, user, bundle: { account_id: "u", kdf: {}, secret_key_enabled: false }, vaults: [vault()], items: [item("a")], cursor: "c1", ...over });
  const snap = (over: Partial<SyncResponse> = {}): Snapshot => mergeSync(null, answer(over))!.snapshot;

  it("vault rows keep manifest, manifest_seq and manifest_ok; the answer's clock and retention are kept", () => {
    const s = snap({ server_time: 1234, trash_days: 30 });
    expect(s.vaults[0]).toMatchObject({ manifest: "aaa", manifest_seq: 2, manifest_prev: "p-aaa", manifest_ok: true });
    expect(s.serverTime).toBe(1234);
    expect(s.trashDays).toBe(30);
    const d = mergeSync(s, answer({ delta: true, items: [], vaults: [vault({ manifest: "bbb", manifest_seq: 3, manifest_prev: "p-bbb", seq: 5 })], cursor: "c2", server_time: 2000, trash_days: 0 }))!.snapshot;
    expect(d.vaults[0]).toMatchObject({ manifest: "bbb", manifest_seq: 3, manifest_prev: "p-bbb" });
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
    expect(isSyncVaultRow(vault({ manifest_prev: null }))).toBe(true);
    expect(isSyncVaultRow(vault({ manifest_prev: 5 as unknown as string }))).toBe(false);
  });

  it("numbers the apps count with are whole numbers from 0 to 2^53 - 1, or the whole answer is refused", () => {
    const bad = [1.5, -1, 2 ** 53, Number.NaN, Number.POSITIVE_INFINITY];
    for (const n of bad) {
      expect(() => mergeSync(null, answer({ vaults: [vault({ seq: n })] })), `seq ${n}`).toThrow();
      expect(() => mergeSync(null, answer({ vaults: [vault({ manifest_seq: n })] })), `manifest_seq ${n}`).toThrow();
      expect(() => mergeSync(null, answer({ vaults: [vault({ key_epoch: n })] })), `key_epoch ${n}`).toThrow();
      expect(() => mergeSync(null, answer({ items: [{ ...item("a"), deleted_at: n }] })), `deleted_at ${n}`).toThrow();
    }
    for (const at of ["7", true, {}]) expect(() => mergeSync(null, answer({ items: [{ ...item("a"), deleted_at: at as unknown as number }] }))).toThrow();
    // The largest numbers pass, and so does `deleted_at` 0 (the core refuses that one: the vault is a mismatch).
    const top = Number.MAX_SAFE_INTEGER;
    expect(mergeSync(null, answer({ vaults: [vault({ seq: top, manifest_seq: top, key_epoch: top })], items: [{ ...item("a"), deleted_at: 0 }] }))).not.toBeNull();
    expect(mergeSync(null, answer({ vaults: [vault({ seq: undefined, manifest_seq: undefined, key_epoch: undefined })] }))).not.toBeNull();
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
    // With the link of the manifest sent (S6): the answer's link must be that one too. A request sent again, stored
    // under its first try's manifest, answers with the same version and another link.
    const L = "a".repeat(43);
    expect(afterWrite(4, 5, true, { sent: 3, answered: 3, sentLink: L, answeredLink: L })).toBe("apply");
    expect(afterWrite(4, 5, true, { sent: 3, answered: 3, sentLink: L, answeredLink: "b".repeat(43) })).toBe("sync");
    expect(afterWrite(4, 5, true, { sent: 3, answered: 3, sentLink: L, answeredLink: undefined })).toBe("sync");
    expect(afterWrite(4, 5, true, { sent: 3, answered: 3, sentLink: L, answeredLink: null })).toBe("sync");
    expect(afterWrite(5, 5, true, { sent: 3, answered: 3, sentLink: L, answeredLink: undefined })).toBe("none");
  });

  it("showing an own write puts its manifest on the vault row, and the next answer replaces it", () => {
    const s = snap();
    const shown = applyOwnWrite(s, { kind: "upsert", row: item("b"), vaultSeq: 5, manifest: { seq: 3, sealed: "bbb", prev: "p-bbb" } });
    expect(shown.vaults[0]).toMatchObject({ manifest: "bbb", manifest_seq: 3, manifest_prev: "p-bbb", seq: 4 });
    expect(knownSeq(shown, "v1")).toBe(5);
    expect(s.vaults[0]).toMatchObject({ manifest: "aaa", manifest_seq: 2 });
    // Without a manifest the row is untouched (a vault that has none).
    expect(applyOwnWrite(s, { kind: "remove", id: "a", vaultId: "v1", vaultSeq: 5 }).vaults).toBe(s.vaults);
    const removed = applyOwnWrite(shown, { kind: "remove", id: "a", vaultId: "v1", vaultSeq: 6, manifest: { seq: 4, sealed: "ccc", prev: "p-ccc" } });
    expect(removed.vaults[0]).toMatchObject({ manifest: "ccc", manifest_seq: 4, manifest_prev: "p-ccc" });
    expect([...removed.items.keys()]).toEqual(["b"]);
    const merged = mergeSync(removed, answer({ delta: true, items: [item("b")], deleted: [{ id: "a", vault_id: "v1" }], vaults: [vault({ manifest: "ccc", manifest_seq: 4, seq: 6 })], cursor: "c2" }))!;
    expect(merged.behind).toBe(false);
    expect(merged.snapshot.vaults[0]).toMatchObject({ manifest: "ccc", manifest_seq: 4, seq: 6 });
  });

  it("a manifest stored by itself (a first one, a baseline) moves only the vault row and its number", () => {
    const s = snap({ vaults: [vault({ manifest: null, manifest_seq: 0 }), vault({ id: "v2" })] });
    const next = applyOwnManifest(s, "v1", { seq: 1, sealed: "first", prev: "p-first" }, 5);
    expect(next.vaults[0]).toMatchObject({ manifest: "first", manifest_seq: 1, manifest_prev: "p-first" });
    // A caller from before `prev` leaves the row's value alone.
    expect(applyOwnManifest(s, "v2", { seq: 3, sealed: "x" }, 5).vaults[1]).toMatchObject({ manifest: "x", manifest_seq: 3, manifest_prev: "p-aaa" });
    expect(next.vaults[1]).toBe(s.vaults[1]);
    expect(next.items).toBe(s.items);
    expect(knownSeq(next, "v1")).toBe(5);
  });
});
