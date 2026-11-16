import { describe, expect, it } from "vitest";
import {
  MALFORMED,
  cleanText,
  diffIsClean,
  isTrustMemoryKey,
  listedAs,
  memoryKey,
  membersDifferText,
  namesFromRows,
  peopleNames,
  pinsKey,
  readIdentity,
  readIdentityRecord,
  readLocalPins,
  readMemberDiff,
  readMembersAnswer,
  readMemory,
  readSeen,
  seenKey,
  addSeen,
  readRosterText,
  readRostersPage,
  readShare,
  rosterMember,
  rosterNumbers,
  rosterUserIds,
  signedByText,
  trustScope,
  updateMemory,
  writeLocalPins,
  type KeyValueStore,
} from "./signing";

const id = { user_id: "u1", public_key: "pk", signing_key: "sk", identity_signature: "sig", x25519_signature: "xsig" };
const legacy = { ...id, signing_key: null, identity_signature: null, x25519_signature: null };

function mapStore(): KeyValueStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return { map, get: (k) => map.get(k) ?? null, set: (k, v) => (v === null ? map.delete(k) : map.set(k, v)) };
}

const roster = (version: number, members: string[] = []) => JSON.stringify({ version, key_epoch: 0, members: members.map((user_id) => ({ user_id })) });

describe("readIdentity", () => {
  it("reads full and legacy identities", () => {
    expect(readIdentity({ ...id, email: "x" })).toEqual(id);
    expect(readIdentity(legacy)).toEqual(legacy);
    expect(readIdentity({ user_id: "u1", public_key: "pk" })).toEqual(legacy);
    expect(readIdentity({ id: "u2", public_key: "pk" }, "id")?.user_id).toBe("u2");
  });

  it("refuses a signing key without both its signatures (no downgrade to legacy), or values that aren't strings", () => {
    expect(readIdentity({ ...id, identity_signature: null })).toBeNull();
    expect(readIdentity({ ...id, x25519_signature: null })).toBeNull();
    expect(readIdentity({ ...legacy, x25519_signature: "x" })).toBeNull();
    expect(readIdentity({ ...id, signing_key: 5 })).toBeNull();
    expect(readIdentity({ ...id, public_key: "" })).toBeNull();
    expect(readIdentity(null)).toBeNull();
  });
});

describe("readIdentityRecord / readShare / readRosterText", () => {
  it("reads a record, none, or malformed", () => {
    const rec = { signing_key: "a", identity_signature: "b", x25519_signature: "x", wrapped_signing_key: "c" };
    expect(readIdentityRecord(null)).toBeNull();
    expect(readIdentityRecord(undefined)).toBeNull();
    expect(readIdentityRecord(rec)).toEqual(rec);
    expect(readIdentityRecord({ ...rec, x25519_signature: undefined })).toBe(MALFORMED);
    expect(readIdentityRecord({ signing_key: "a" })).toBe(MALFORMED);
  });

  it("reads a share with its signer's name and email cleaned; a broken one is never read as 'not signed'", () => {
    expect(readShare(null)).toBeNull();
    expect(readShare(undefined)).toBeNull();
    expect(readShare({ signature: "s", signer: { ...id, email: "a@x​", name: "A\nB" }, signer_deleted: true })).toEqual({
      signature: "s",
      signer: { ...id, email: "a@x", name: "A B" },
      signerDeleted: true,
    });
    expect(readShare({ signature: "s", signer: { ...id } })).toEqual({ signature: "s", signer: { ...id, email: "", name: "" }, signerDeleted: false });
    expect(readShare({ signature: "", signer: id })).toBe(MALFORMED);
    expect(readShare({ signature: "s", signer: { user_id: "u" } })).toBe(MALFORMED);
    // A legacy identity can't have signed anything.
    expect(readShare({ signature: "s", signer: legacy })).toBe(MALFORMED);
    expect(readShare("x")).toBe(MALFORMED);
  });

  it("reads roster text", () => {
    expect(readRosterText(null)).toBeNull();
    expect(readRosterText("{}")).toBe("{}");
    expect(readRosterText(5)).toBe(MALFORMED);
  });
});

describe("readMembersAnswer", () => {
  const row = { ...id, email: "a@x", name: "A", role: "owner", key_kind: "account", share: null, status: "active" };

  it("reads members with identities, key kinds and shares, and the roster fields", () => {
    const a = readMembersAnswer({ members: [row], key_epoch: 3, member_roster: "{}", member_roster_seq: 2 });
    expect(a).toEqual({ members: [row], keyEpoch: 3, roster: "{}", rosterSeq: 2 });
    expect(readMembersAnswer({ members: [{ user_id: "u", email: "", name: "", role: "read", public_key: "pk" }] })).toMatchObject({ roster: null, rosterSeq: 0, keyEpoch: undefined });
  });

  it("cleans names and emails (M3)", () => {
    const a = readMembersAnswer({ members: [{ ...row, email: "a@x‮", name: `${"n".repeat(300)}\u0000` }] })!;
    expect(a.members[0].email).toBe("a@x");
    expect(Array.from(a.members[0].name)).toHaveLength(128);
  });

  it("refuses the whole list when one row or field is unusable, or a user is listed twice", () => {
    expect(readMembersAnswer({ members: [row, { ...row, user_id: "u2", public_key: 1 }] })).toBeNull();
    expect(readMembersAnswer({ members: [row, row] })).toBeNull();
    expect(readMembersAnswer({ members: [{ ...row, identity_signature: null }] })).toBeNull();
    expect(readMembersAnswer({ members: [row], member_roster: 5 })).toBeNull();
    expect(readMembersAnswer({ members: [row], member_roster_seq: -1 })).toBeNull();
    expect(readMembersAnswer({ members: [row], key_epoch: 1.5 })).toBeNull();
    expect(readMembersAnswer({})).toBeNull();
  });

  it("keeps a malformed share as malformed", () => {
    expect(readMembersAnswer({ members: [{ ...row, share: { signature: 1 } }] })?.members[0].share).toBe(MALFORMED);
  });

  it("gives the core only identity, role and the listed email", () => {
    const a = readMembersAnswer({ members: [row] })!;
    expect(rosterMember(a.members[0], "owner")).toEqual({ ...id, role: "owner", email: "a@x" });
    expect(rosterMember(a.members[0], "admin").role).toBe("admin");
  });
});

describe("rosters", () => {
  it("reads a page of rosters", () => {
    expect(readRostersPage({ rosters: ["a", "b"], more: true })).toEqual({ rosters: ["a", "b"], more: true });
    expect(readRostersPage({ rosters: ["a", 1] })).toBeNull();
    expect(readRostersPage({})).toBeNull();
  });

  it("reads version, key epoch and members from roster text", () => {
    expect(rosterNumbers(JSON.stringify({ version: 2, key_epoch: 0 }))).toEqual({ version: 2, keyEpoch: 0 });
    expect(rosterNumbers(JSON.stringify({ version: "2", key_epoch: 0 }))).toBeNull();
    expect(rosterNumbers("not json")).toBeNull();
    expect(rosterUserIds(roster(1, ["a", "b"]))).toEqual(["a", "b"]);
    expect(rosterUserIds("x")).toEqual([]);
  });
});

describe("device memory", () => {
  const scope = trustScope("https://vault.example", "u1");

  it("is kept per server and account (H1, desktop change server)", () => {
    expect(memoryKey(scope)).toBe("pa.vault-trust.https://vault.example|u1");
    expect(pinsKey(trustScope("https://other.example", "u1"))).toBe("pa.key-pins.https://other.example|u1");
    expect(isTrustMemoryKey(memoryKey(scope))).toBe(true);
    expect(isTrustMemoryKey(pinsKey(scope))).toBe(true);
    expect(isTrustMemoryKey("pa.rotate.u1")).toBe(false);
  });

  it("merges writes: rosters only go up, marks only turn on, the own identity is kept", () => {
    const s = mapStore();
    updateMemory(s, scope, { on: true, own: "h1", vaults: { v1: { roster: roster(2), signed: true }, v2: { signed: true } } });
    // Another tab writes an older roster and no marks: nothing goes back.
    updateMemory(s, scope, { own: "h2", vaults: { v1: { roster: roster(1) }, v2: {} } });
    const m = readMemory(s, scope);
    expect(m).toEqual({ on: true, own: "h1", vaults: { v1: { roster: roster(2), signed: true }, v2: { signed: true } }, generated: [] });
    updateMemory(s, scope, { vaults: { v1: { roster: roster(3) } } });
    expect(readMemory(s, scope).vaults.v1.roster).toBe(roster(3));
    expect(readMemory(s, trustScope("https://vault.example", "u2"))).toEqual({ on: false, own: null, vaults: {}, generated: [] });
  });

  it("drops malformed entries", () => {
    const s = mapStore();
    s.map.set(memoryKey(scope), JSON.stringify({ on: "yes", vaults: { v: { roster: 5, signed: "yes" }, w: 3, x: { roster: "not json" } } }));
    expect(readMemory(s, scope)).toEqual({ on: false, own: null, vaults: { v: {}, x: {} }, generated: [] });
    s.map.set(memoryKey(scope), "{");
    expect(readMemory(s, scope)).toEqual({ on: false, own: null, vaults: {}, generated: [] });
  });

  it("never writes over a stored record it can't read (memory, local key pins, vaults seen)", () => {
    const s = mapStore();
    s.map.set(memoryKey(scope), "{");
    expect(updateMemory(s, scope, { on: true, own: "h1" })).toBeNull();
    expect(s.map.get(memoryKey(scope))).toBe("{");
    s.map.set(pinsKey(scope), "[1]");
    expect(writeLocalPins(s, scope, { seq: 1, sealed: "x", dirty: true })).toBe(false);
    expect(s.map.get(pinsKey(scope))).toBe("[1]");
    s.map.set(seenKey(scope), "nope");
    addSeen(s, scope, ["v1"]);
    expect(s.map.get(seenKey(scope))).toBe("nope");
  });

  it("keeps the identity hashes generated here (newest 4) and a 'missing' list that only shrinks", () => {
    const s = mapStore();
    for (const h of ["a", "b", "c", "d", "e"]) updateMemory(s, scope, { generated: h });
    expect(readMemory(s, scope).generated).toEqual(["b", "c", "d", "e"]);
    updateMemory(s, scope, { missing: { ids: ["v1", "v2"], why: "device" } });
    expect(readMemory(s, scope)).toMatchObject({ missing: ["v1", "v2"], missingWhy: "device" });
    // Never grows again: a later write only narrows it.
    updateMemory(s, scope, { missing: { ids: ["v2", "v3"], why: "pins" } });
    expect(readMemory(s, scope)).toMatchObject({ missing: ["v2"], missingWhy: "device" });
  });

  it("records the vaults seen here per server and account (null before anything was recorded)", () => {
    const s = mapStore();
    expect(readSeen(s, scope)).toBeNull();
    addSeen(s, scope, []);
    expect(readSeen(s, scope)).toEqual([]);
    addSeen(s, scope, ["v1", "v2"]);
    addSeen(s, scope, ["v2", "v3"]);
    expect(readSeen(s, scope)).toEqual(["v1", "v2", "v3"]);
    expect(isTrustMemoryKey(seenKey(scope))).toBe(true);
  });

  it("keeps the local key pins copy with the higher version", () => {
    const s = mapStore();
    writeLocalPins(s, scope, { seq: 3, sealed: "x", dirty: true });
    expect(readLocalPins(s, scope)).toEqual({ seq: 3, sealed: "x", dirty: true });
    writeLocalPins(s, scope, { seq: 2, sealed: "older", dirty: false });
    expect(readLocalPins(s, scope)?.sealed).toBe("x");
    writeLocalPins(s, scope, { seq: 3, sealed: "y", dirty: false });
    expect(readLocalPins(s, scope)?.sealed).toBe("y");
    s.map.set(pinsKey("other"), JSON.stringify({ seq: -1, sealed: "x" }));
    expect(readLocalPins(s, "other")).toBeNull();
  });
});

describe("wording", () => {
  it("cleans names: one line, no invisible characters, at most 128 characters", () => {
    expect(cleanText("a‮b\nc")).toBe("ab c");
    expect(cleanText(5)).toBe("");
  });

  it("names the signer by the pinned email first, and a deleted account", () => {
    expect(signedByText("alex@example.com", { name: "Evil", email: "evil@example.com" }, false)).toBe("Signed by alex@example.com");
    expect(signedByText(null, { name: "Alex", email: "alex@example.com" }, false)).toBe("Signed by alex@example.com");
    expect(signedByText(null, { name: "", email: "alex@example.com" }, true)).toBe("Signed by alex@example.com (account deleted)");
  });

  it("shows a different listed email only as 'listed by your server as …'", () => {
    expect(listedAs("a@x", "b@x")).toBe("listed by your server as b@x");
    expect(listedAs("a@x", "A@X")).toBeNull();
    expect(listedAs(null, "b@x")).toBeNull();
  });

  it("names who differs, never by a raw user id (L1)", () => {
    const nameOf = namesFromRows([
      { user_id: "u1", email: "a@x", name: "A" },
      { user_id: "u2", email: "", name: "Bea" },
    ]);
    expect(peopleNames(["u1", "u2", "u9"], nameOf)).toEqual(["a@x", "Bea", "someone your server lists"]);
    expect(peopleNames(["u8", "u9"], nameOf)).toEqual(["2 people your server lists"]);
    expect(membersDifferText(["u1", "u9"], nameOf)).toBe("The server lists members your vault's signed member list doesn't: a@x, someone your server lists. PassAuth didn't change the key.");
    expect(diffIsClean({ unknown: [], identity_changed: [], role_changed: [], missing: ["u3"] })).toBe(true);
  });

  it("reads a members_changed answer", () => {
    expect(readMemberDiff({ unknown: ["a"], identity_changed: [], role_changed: [], missing: [] })).toEqual({ unknown: ["a"], identity_changed: [], role_changed: [], missing: [] });
    expect(readMemberDiff({ unknown: [1] })).toBeNull();
    expect(readMemberDiff(undefined)).toBeNull();
  });
});
