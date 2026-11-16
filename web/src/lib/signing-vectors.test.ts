/**
 * The `signedSharing` vectors (testdata/vectors.json, made by the core and cross-checked by generate-vectors.mjs)
 * through the WASM build the web vault and desktop app use: the same steps as `crates/core/tests/vectors.rs`, so every
 * check answers as it does in the Rust, Swift and Kotlin apps.
 */
import { beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/passauth_core";
import { loadCore, signedVectors, vectorAccounts, type SignedVectors, type VectorMember } from "./test-core";

let v: SignedVectors;
let accounts: ReturnType<typeof vectorAccounts>;
let signers: Map<string, core.SigningIdentity>;
let vaultKey: core.VaultKey;
let secondKey: core.VaultKey;
const rosters = new Map<string, string>();

beforeAll(async () => {
  await loadCore();
  v = await signedVectors();
  accounts = vectorAccounts(v);
  signers = new Map([...accounts].map(([name, a]) => [name, a.account.openSigningIdentity(a.record)]));
  const alice = accounts.get("alice")!.account;
  vaultKey = alice.openVaultKey(v.vault.id, v.vault.wrappedKeyV2, "account", 0, false);
  secondKey = alice.openVaultKey(v.vault.id, v.vault.secondKeyV2, "account", 0, false);
  for (const r of v.rosters) rosters.set(r.name, r.json);
});

const who = (name: string, legacy: boolean) =>
  legacy ? (accounts.get(name)!.account.legacyIdentity() as core.PublicIdentity) : (signers.get(name)!.publicIdentity() as core.PublicIdentity);
const roster = (name: string | null) => (name === null ? null : rosters.get(name)!);
const nameOf = (json: string) => [...rosters].find(([, j]) => j === json)?.[0] ?? json;
const inputs = (list: VectorMember[], withEmail = true): core.RosterMemberInput[] =>
  list.map((m) => {
    const [n, role, legacy, email] = m as [string, string, boolean?, (string | boolean)?];
    return { ...who(n, !!legacy), role, email: withEmail && typeof email === "string" ? email : null };
  });

function outcome(run: () => unknown): { expected?: unknown; error?: string } {
  try {
    return { expected: run() };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}
const want = (c: { expected?: unknown; error?: string }) => ("error" in c && c.error !== undefined ? { error: c.error } : { expected: c.expected });

describe("signed sharing vectors", () => {
  it("opens account wraps by format, epoch and the legacy rule, and gives the key ids", () => {
    const alice = accounts.get("alice")!.account;
    for (const c of v.openings) {
      const wrap = (v.vault as Record<string, string>)[c.wrap];
      const got = outcome(() => alice.openVaultKey(v.vault.id, wrap, "account", c.keyEpoch, c.legacyAllowed).keyId(v.vault.id));
      expect(got, JSON.stringify(c)).toEqual(want(c));
    }
    expect(vaultKey.keyId(v.vault.id)).toBe(v.keyIds.first);
    expect(secondKey.keyId(v.vault.id)).toBe(v.keyIds.second);
  });

  it("opens every identity and gives the same public identity, hashes and fingerprint", () => {
    for (const i of v.identities) {
      const pub = who(i.name, false);
      expect(pub).toEqual(i.publicIdentity);
      expect(who(i.name, true)).toEqual(i.legacyIdentity);
      expect(core.verifyIdentity(pub)).toEqual({ user_id: pub.user_id, signing: true, hash: i.hash, legacy_hash: i.legacyHash, fingerprint: i.fingerprint });
      expect(signers.get(i.name)!.fingerprint()).toBe(i.fingerprint);
      expect(signers.get(i.name)!.identityHash()).toBe(i.hash);
      expect(core.verifyIdentity(who(i.name, true)).signing).toBe(false);
    }
  });

  it("refuses a forged upgrade (someone's X25519 key paired with another signing key) and a swapped key", () => {
    expect(() => core.verifyIdentity(v.forgedUpgrade)).toThrow("bad_signature");
    const pub = who("alice", false);
    expect(() => core.verifyIdentity({ ...pub, public_key: who("bob", false).public_key })).toThrow("bad_signature");
  });

  it("signs every share byte-exactly and verifies it", () => {
    for (const c of v.shares) {
      const to = who(c.recipient, c.recipientLegacy);
      const signer = signers.get(c.signer)!;
      expect(signer.signShare(c.vaultId, to, c.role, c.keyEpoch, c.sealedKey)).toBe(c.signature);
      expect(core.verifyShare(c.vaultId, to, c.role, c.keyEpoch, c.sealedKey, signer.publicIdentity(), c.signature).user_id).toBe(signer.userId());
      expect(() => core.verifyShare(c.vaultId, to, c.role === "read" ? "write" : "read", c.keyEpoch, c.sealedKey, signer.publicIdentity(), c.signature)).toThrow(
        "bad_signature",
      );
    }
  });

  it("signs every valid roster byte-exactly through a review, and its key matches it", () => {
    for (const r of v.rosters) {
      if (r.rogue) continue;
      const signer = signers.get(r.signer)!;
      const members = inputs(r.members);
      const review = core.rosterReview(v.vault.id, roster(r.previous), signer.publicIdentity(), members, null);
      expect(signer.signRoster(vaultKey, v.vault.id, roster(r.previous), r.keyEpoch, members, review.digest), r.name).toBe(r.json);
      expect(vaultKey.matchesRoster(v.vault.id, r.json)).toBe(true);
      expect(vaultKey.matchesRoster("00000000-0000-4000-8000-0000000000f2", r.json)).toBe(false);
    }
  });

  it("refuses to sign a list other than the one reviewed (review_mismatch)", () => {
    const signer = signers.get("alice")!;
    const reviewed = core.rosterReview(v.vault.id, null, signer.publicIdentity(), inputs([["alice", "owner"], ["bob", "write"]]), null);
    expect(() => signer.signRoster(vaultKey, v.vault.id, null, 0, inputs([["alice", "owner"], ["bob", "admin"]]), reviewed.digest)).toThrow("review_mismatch");
  });

  it("computes the key commitments", () => {
    for (const c of v.commitments) expect(vaultKey.commitment(v.vault.id, c.keyEpoch)).toBe(c.commitment);
  });

  it("verifies roster chains (vault id bound, hierarchy, exact end)", () => {
    for (const c of v.chains) {
      const got = outcome(() => nameOf(core.verifyRosterChain(c.vault, roster(c.trusted), c.newer.map((n) => roster(n)!), roster(c.latest)!)));
      expect(got, JSON.stringify(c)).toEqual(want(c));
    }
  });

  it("compares roster heads", () => {
    for (const c of v.heads) {
      const got = outcome(() => core.rosterHead(c.vault, roster(c.remembered), roster(c.latest)));
      expect(got, JSON.stringify(c)).toEqual(want(c));
    }
  });

  it("compares member lists, and reads member and signer roles (a legacy listing grants no authority)", () => {
    for (const c of v.memberDiffs) expect(core.compareMembers(roster(c.roster)!, inputs(c.members, false))).toEqual(c.expected);
    for (const c of v.rosterRoles) {
      const id = who(c.identity[0], c.identity[1]);
      expect(core.rosterMemberRole(roster(c.roster)!, id) ?? null, JSON.stringify(c)).toEqual(c.member);
      expect(core.rosterSignerRole(roster(c.roster)!, id) ?? null, JSON.stringify(c)).toEqual(c.signer);
    }
  });

  it("pins identities and checks them (upgrades, changes, email conflicts)", () => {
    let pins = core.pinSet(null, who("bob", false), "bob@example.com", true, 1000);
    pins = core.pinSet(pins, who("carol", true), "carol@example.com", false, 1000);
    expect(pins).toEqual(v.keyPins);
    for (const c of v.pinChecks) expect(core.pinCheck(v.keyPins, who(c.identity[0], c.identity[1]), c.email), JSON.stringify(c)).toBe(c.expected);
  });

  it("reviews member lists as the core does", () => {
    for (const c of v.reviews) {
      const got = core.rosterReview(v.vault.id, roster(c.previous), signers.get(c.signer)!.publicIdentity(), inputs(c.members), v.keyPins);
      expect(got, c.name).toEqual(c.expected);
    }
  });

  it("checks key epochs with key ids, raises, merges, leaves and grandfathers pins", () => {
    for (const c of v.epochChecks) expect(core.epochCheck(c.pinned, c.current)).toBe(c.expected);
    const ep = (k: core.VaultKey, e: number) => k.epochPin(v.vault.id, e);
    const hashOf = (name: string) => v.rosters.find((r) => r.name === name)!.hash;
    // A key this device gave the vault itself (`pinsRecordRotation`): a roster version only ever with its hash.
    const record = (p: core.KeyPins | null, current: core.EpochPin, rosterVersion: number | null = null, name: string | null = null) =>
      core.pinsRecordRotation(p, v.vault.id, "sealed", current, rosterVersion, name ? hashOf(name) : null);
    const withEpoch = record(v.keyPins, ep(vaultKey, 1), 2, "v2");
    expect(withEpoch).toEqual(v.keyPinsWithEpoch);
    expect(outcome(() => record(withEpoch, ep(vaultKey, 0), 2, "v2")).error).toBe("rollback");
    expect(outcome(() => record(withEpoch, ep(secondKey, 2), 3)).error).toBeDefined();
    for (const c of v.pinsEpochChecks) expect(core.pinsEpochCheck(withEpoch, v.vault.id, c.current, c.rosterVersion), JSON.stringify(c)).toBe(c.expected);
    const raised = record(withEpoch, ep(secondKey, 2), 3, "v3");
    expect(raised).toEqual(v.keyPinsRaised);
    const other = record(null, ep(secondKey, 2));
    expect(core.mergePins(withEpoch, other).epochs).toEqual(v.mergedEpochs);
    const left = core.pinsLeave(raised, v.vault.id, 3, 2000);
    expect(left).toEqual(v.keyPinsLeft);
    // Grandfathered vaults are bound to the key id they have now (round 5).
    const candidates = [{ vault_id: v.vault.id, key_id: v.keyIds.first }];
    const grandfathered = core.pinsGrandfather(v.keyPins, candidates, true);
    expect(grandfathered).toEqual(v.keyPinsGrandfathered);
    expect(outcome(() => core.pinsGrandfather(v.keyPins, [v.vault.id] as never, true)).error).toBeDefined();
    // Trust memory missing (an identity from before, no key pins): nothing grandfathered.
    const withheld = core.pinsGrandfather(v.keyPins, candidates, false);
    expect(withheld).toEqual(v.keyPinsWithheld);
    const unsigned = record(grandfathered, ep(vaultKey, 1));
    expect(unsigned).toEqual(v.keyPinsUnsigned);
    for (const r of v.rosters) expect(core.rosterHash(r.json), r.name).toBe(r.hash);
    const rosterMax = core.pinsObserve(withEpoch, {
      vault_id: v.vault.id,
      key_kind: "sealed",
      key: ep(vaultKey, 1),
      roster_version: 3,
      roster_hash: hashOf("v3"),
      signed_share: true,
      paused: false,
    }).pins;
    expect(rosterMax).toEqual(v.keyPinsRosterMax);
    // An account row marks the pin `own` (a personal vault must never silently become one someone else sealed).
    const own = core.pinsObserve(null, {
      vault_id: v.vault.id,
      key_kind: "account",
      key: ep(vaultKey, 1),
      roster_version: null,
      roster_hash: null,
      signed_share: false,
      paused: false,
    }).pins;
    expect(own).toEqual(v.keyPinsOwn);
    const sets: Record<string, core.KeyPins | null> = { none: null, withEpoch, raised, left, grandfathered, withheld, unsigned, rosterMax, own };
    for (const c of v.admissions) expect(core.pinsAdmit(sets[c.pins], c.observation), JSON.stringify(c)).toEqual(c.expected);
    // Some admissions carry `chain_hashes` (round 4): a chain that forks the pinned roster is refused.
    expect(v.admissions.some((c) => c.observation.chain_hashes)).toBe(true);
    // Accepting (consents, invitations): pins like pinsRecordRotation plus the roster hash and `own`, or throws what admission refuses.
    for (const c of v.accepts) expect(outcome(() => core.pinsAccept(sets[c.pins], c.observation)), JSON.stringify(c)).toEqual(want(c));
    // Merges are monotone: retired keys never come back, tombstones absorb the pins they beat, re-joins are explicit.
    for (const c of v.merges) expect(outcome(() => core.mergePins(c.base, c.ours)), c.name).toEqual(want(c));
    // A device's last-known copy merged into a newer server copy (round 5 M1): the server wins for people pinned with
    // another identity (no rewrite loop); keys, tombstones, verified marks are kept; another own identity throws.
    for (const c of v.mergesLastKnown) expect(outcome(() => core.pinsMergeLastKnown(c.base, c.lastKnown)), c.name).toEqual(want(c));
    // Declines (round 5 M2): never a vault held, a current row or one left; else a tombstone at roster version 0.
    for (const c of v.declines) expect(core.pinsDecline(sets[c.pins], c.vaultId, c.currentRow, 3000), JSON.stringify([c.pins, c.vaultId, c.currentRow])).toEqual(c.expected);
    let step = grandfathered;
    for (const c of v.observations) {
      const observed = core.pinsObserve(step, c.observation);
      expect(observed, JSON.stringify(c.observation)).toEqual(c.expected);
      // `accept`: the user accepted that step's consent (`first_signed`: re-signed at the same key, round 5).
      step = c.accept ? core.pinsAccept(step, c.observation) : observed.pins;
      if (c.accept) expect(step, "accepted").toEqual(c.accepted);
    }
    for (const c of v.legacyWraps) expect(core.pinsLegacyWrapAllowed(sets[c.pins], v.vault.id)).toBe(c.expected);
  });

  it("normalizes emails for comparing and showing (punycode domains)", () => {
    for (const c of v.emails) expect(core.normalizeEmail(c.email), c.email).toBe(c.expected);
  });

  it("remembers the account's own identity and finds another one listed", () => {
    const own = v.ownIdentity;
    expect(signers.get("alice")!.identityHash()).toBe(own.hash);
    const withOwn = core.pinsSetOwnIdentity(v.keyPins, own.hash);
    expect(withOwn).toEqual(own.pins);
    for (const c of own.checks) expect(core.pinsCheckOwnIdentity(c.pins === "withOwn" ? withOwn : null, c.listed), JSON.stringify(c)).toBe(c.expected);
    expect(() => core.pinsSetOwnIdentity(withOwn, v.identities.find((i) => i.name === "bob")!.hash)).toThrow("identity_mismatch");
  });

  it("seals key pins with the account key and refuses another version", () => {
    const alice = accounts.get("alice")!.account;
    const sealed = alice.sealKeyPins(v.keyPins, 3);
    expect(alice.openKeyPins(sealed, 3).pins).toEqual(v.keyPins.pins);
    expect(() => alice.openKeyPins(sealed, 2)).toThrow("rollback");
    expect(() => accounts.get("bob")!.account.openKeyPins(sealed, 3)).toThrow("decrypt_failed");
  });

  it("refuses another account's signing identity record", () => {
    const alice = accounts.get("alice")!.account;
    expect(() => alice.openSigningIdentity(accounts.get("bob")!.record)).toThrow(/identity_mismatch|decrypt_failed/);
  });
});
