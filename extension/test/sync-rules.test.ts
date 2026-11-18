// The extension's own delta-sync rules (background/sync-rules.ts): the offline copy's shape (cursor, vault numbers and
// rows in one record), when a /sync/revision answer means "sync", reading live-sync messages, the reconnect delay.

import type { Snapshot } from "@web/lib/delta";
import type { SyncItemRow, SyncVaultRow } from "@web/lib/types";
import { expect, test } from "vitest";
import { backoffMs, closedFor, fromStored, isStale, olderAnswer, readExtras, readLiveMessage, readRevision, socketUrl, toStored } from "../src/background/sync-rules";

const vault = (id: string, seq?: number): SyncVaultRow => ({ id, meta: "m", role: "owner", wrapped_key: `${id}-k`, key_kind: "account", key_epoch: 1, ...(seq === undefined ? {} : { seq }) });
const row = (id: string, vaultId = "v1"): SyncItemRow => ({ id, vault_id: vaultId, item_key: `k-${id}`, data: `d-${id}`, revision: 1, deleted_at: null, created_at: 1, updated_at: 1 });

const snapshot = (over: Partial<Snapshot> = {}): Snapshot => ({
  revision: 10,
  cursor: "cur",
  user: { id: "u1", email: "a@example.com", name: "A", email_verified: true },
  bundle: { account_id: "acc", kdf: {}, secret_key_enabled: false },
  vaults: [vault("v1", 5), vault("v2", 7)],
  items: new Map([
    ["i1", row("i1")],
    ["i2", row("i2", "v2")],
  ]),
  invitations: [],
  own: {},
  ...over,
});

test("the offline copy: one full-answer-shaped record with its cursor, vault numbers, rows and own writes; read back the same", () => {
  const s = snapshot({ own: { v1: 6 } });
  const stored = toStored(s);
  expect(stored.cursor).toBe("cur");
  expect(stored.vaults.map((v) => v.seq)).toStrictEqual([5, 7]);
  expect(stored.items.map((r) => r.id)).toStrictEqual(["i1", "i2"]);
  expect(stored.own).toStrictEqual({ v1: 6 });
  // Never a delta: older versions of the extension read it as an ordinary answer.
  expect("delta" in stored).toBe(false);
  const back = fromStored(structuredClone(stored));
  if (!back) throw new Error("the copy should read back");
  expect(back.cursor).toBe("cur");
  expect([...back.items.keys()]).toStrictEqual(["i1", "i2"]);
  expect(back.own).toStrictEqual({ v1: 6 });
  expect(back.revision).toBe(10);
});

test("a copy from before delta sync (no cursor, no seq) has no cursor; damaged rows and own numbers are left out", () => {
  const old = {
    revision: 3,
    user: { id: "u1", email: "", name: "", email_verified: true },
    bundle: { account_id: "acc", kdf: {}, secret_key_enabled: false },
    vaults: [vault("v1")],
    items: [row("i1"), { nope: 1 }],
  };
  const s = fromStored({ ...old, own: { v1: "x", v2: 4 } } as never);
  if (!s) throw new Error("the copy should read back");
  expect(s.cursor).toBe(null);
  expect([...s.items.keys()]).toStrictEqual(["i1"]);
  expect(s.own).toStrictEqual({ v2: 4 });
  expect(s.invitations).toStrictEqual([]);
});

test("the offline copy is checked like a server's answer before anything reaches the core", () => {
  const stored = toStored(snapshot());
  // Vault rows whose key fields aren't text are left out (they stay closed), like rows of a /sync answer.
  const damaged = { ...stored, vaults: [...stored.vaults, { ...vault("v3"), wrapped_key: 7 }, { ...vault("v4"), meta: { length: 9e8 } }, null] };
  expect(fromStored(damaged as never)?.vaults.map((v) => v.id)).toStrictEqual(["v1", "v2"]);
  // Not an answer at all (no user, a bundle without an account id, no lists): no copy; the vault syncs instead.
  for (const broken of [
    { ...stored, user: null },
    { ...stored, bundle: { account_id: 5 } },
    { ...stored, vaults: "x" },
    { ...stored, items: null },
  ]) {
    expect(fromStored(broken as never)).toBe(null);
  }
});

test("/sync/revision: without vault numbers any other revision counts (ROUND 3: a lower one too, a server that went back)", () => {
  expect(isStale({ revision: 10 }, snapshot())).toBe(false);
  expect(isStale({ revision: 11 }, snapshot())).toBe(true);
  // A copy without a cursor (an older server) is judged by the revision alone, even if the answer has numbers.
  expect(isStale({ revision: 10, vaults: { v1: 99 } }, snapshot({ cursor: null }))).toBe(false);
  // No copy at all: sync.
  expect(isStale({ revision: 1 }, null)).toBe(true);
});

test("/sync/revision with vault numbers: another revision, a different number, a new vault or a vault gone means sync", () => {
  const s = snapshot();
  expect(isStale({ revision: 10, vaults: { v1: 5, v2: 7 } }, s)).toBe(false);
  expect(isStale({ revision: 11, vaults: { v1: 5, v2: 7 } }, s), "profile or membership change").toBe(true);
  expect(isStale({ revision: 10, vaults: { v1: 6, v2: 7 } }, s)).toBe(true);
  expect(isStale({ revision: 10, vaults: { v1: 5, v2: 7, v3: 1 } }, s), "a vault shared with the account").toBe(true);
  expect(isStale({ revision: 10, vaults: { v1: 5 } }, s), "a vault gone").toBe(true);
  // Own writes shown without asking count as known numbers.
  expect(isStale({ revision: 10, vaults: { v1: 6, v2: 7 } }, snapshot({ own: { v1: 6 } }))).toBe(false);
});

test("reading /sync/revision answers", () => {
  expect(readRevision({ revision: 3, vaults: { a: 1 } })).toStrictEqual({ revision: 3, vaults: { a: 1 } });
  expect(readRevision({ revision: 3 })).toStrictEqual({ revision: 3 });
  expect(readRevision({ revision: 3, vaults: { a: "1" } }), "a bad number makes the list unknown").toStrictEqual({ revision: 3 });
  expect(readRevision({ revision: "3" })).toBe(null);
  expect(readRevision(null)).toBe(null);
});

test("live-sync messages: hello, sync (revision, vault numbers, origin), logout; anything else is ignored", () => {
  expect(readLiveMessage('{"type":"hello","origin":"o1"}')).toStrictEqual({ type: "hello", origin: "o1" });
  expect(readLiveMessage('{"type":"sync","revision":7,"vaults":{"v1":3},"origin":"o1"}')).toStrictEqual({ type: "sync", revision: 7, vaults: { v1: 3 }, origin: "o1" });
  expect(readLiveMessage('{"type":"sync","revision":8,"vaults":{}}')).toStrictEqual({ type: "sync", revision: 8, vaults: {} });
  expect(readLiveMessage('{"type":"logout"}')).toStrictEqual({ type: "logout" });
  for (const bad of ["", "nope", "[]", '{"type":"hello"}', '{"type":"other"}', "null", 42]) expect(readLiveMessage(bad), String(bad)).toBe(null);
});

test("reconnect delay: 1 s doubling to a minute, ±20%, never above a minute", () => {
  expect([0, 1, 2, 3, 4, 5, 6, 7, 20].map((n) => backoffMs(n, 0.5))).toStrictEqual([1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000]);
  expect(backoffMs(0, 0)).toBe(800);
  expect(backoffMs(0, 0.999999)).toBe(1200);
  expect(backoffMs(9, 1)).toBe(60000);
});

test("socket address: wss for https, the token encoded in the query", () => {
  expect(socketUrl("https://vault.test", "a+b/c")).toBe("wss://vault.test/api/ws?access_token=a%2Bb%2Fc");
  expect(socketUrl("http://localhost:8091/sub", "t")).toBe("ws://localhost:8091/sub/api/ws?access_token=t");
});

test("two_step_required: the message, and the close (1008, two_step_required) that means don't come back", () => {
  expect(readLiveMessage('{"type":"two_step_required"}')).toStrictEqual({ type: "two_step_required" });
  expect(closedFor(1008, "two_step_required")).toBe("two_step");
  for (const [code, reason] of [
    [1008, "other"],
    [1006, "two_step_required"],
    [1000, ""],
  ] as const)
    expect(closedFor(code, reason)).toBe(null);
});

test("ROUND 3 (T2): an answer with a lower revision than the one shown is dropped only when it can be a race; otherwise the whole account is fetched once and that answer is judged", () => {
  // Something else was shown since the request was sent (another answer adopted, an own write applied): simply late.
  expect([olderAnswer(true, true), olderAnswer(true, false)]).toStrictEqual(["drop", "drop"]);
  // Nothing was: the server itself went back (restored from a backup). Never ignored.
  expect(olderAnswer(false, true), "a delta is of no use: everything, once").toBe("full");
  expect(olderAnswer(false, false), "a whole answer is judged like any other").toBe("judge");
  // The cheap revision check finds a server that went back too (no vault numbers: an older server).
  expect(isStale({ revision: 9 }, snapshot())).toBe(true);
  expect(isStale({ revision: 9, vaults: { v1: 99 } }, snapshot({ cursor: null }))).toBe(true);
});

test("ROUND 3 (T1c): a row kept aside is read from the offline copy also while the copy has a row of that id (the last opened copy of an item that doesn't open now)", () => {
  const row = (id: string, data: string) => ({ id, vault_id: "v1", item_key: `k-${id}`, data, revision: 1, deleted_at: null });
  const extras = readExtras({ items: [row("i1", "now")], stash: [row("i1", "before"), row("i2", "gone"), { id: "i3", vault_id: "v1", revision: 1, deleted_at: null }] });
  expect([...extras.stash.keys()]).toStrictEqual(["i1", "i2"]);
  expect(extras.stash.get("i1")?.data).toBe("before");
});
