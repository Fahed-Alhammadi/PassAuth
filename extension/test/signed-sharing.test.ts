// Signed sharing in the extension (background/signed-sharing.ts and its use in background/vault.ts), with the real core:
// - the `signedSharing` section of testdata/vectors.json through the WASM build the extension bundles;
// - `checkVault` on rows a server could send, one regression test per review finding (signed sharing round 2:
//   H1 forged identities and the account id, H3 planted rows and consent, H4 epochs and key ids, L1 vault ids, L5/L6
//   own role, M2 caps, M3 names, pins written only after every check, paused, downgrades);
// - the worker end to end: a verified shared vault's logins are used, a planted one waits for consent (and can be
//   accepted from the signer shown), a sync for another account is refused, a lost own identity pauses sharing, the
//   verdicts survive an offline reopen, older servers keep working, the identity is made and uploaded once, the key
//   pins are written, and a changed key can be trusted again (only the one shown).

import { beforeEach, expect, test, vi } from "vitest";
import * as core from "../src/wasm/passauth_core";
import { type FakeChrome, installChrome } from "./chrome";
import { accountRecord, type FakeServer, fakeServer } from "./fake-server";
import { fromB64u } from "./helpers";

const vault = await import("../src/background/vault");
const storage = await import("../src/background/storage");
const { forgetServerFeatures, SERVER_UPDATE_TEXT, UNREACHABLE_TEXT } = await import("../src/background/api");
const ss = await import("../src/background/signed-sharing");

// ------------------------------------------------------------------ vectors

type Member = [string, string, boolean?, (string | boolean)?];
interface Outcome {
  expected?: unknown;
  error?: string;
}
interface SharingVectors {
  accounts: { name: string; id: string; sessionBytes: string; record: core.IdentityRecord }[];
  vault: { id: string; wrappedKey: string; wrappedKeyV2: string; secondKeyV2: string };
  openings: ({ wrap: "wrappedKey" | "wrappedKeyV2"; keyEpoch: number; legacyAllowed: boolean } & Outcome)[];
  keyIds: { first: string; second: string };
  identities: { name: string; publicIdentity: core.PublicIdentity; legacyIdentity: core.PublicIdentity; hash: string; legacyHash: string; fingerprint: string }[];
  forgedUpgrade: core.PublicIdentity;
  shares: { signer: string; recipient: string; recipientLegacy: boolean; vaultId: string; role: string; keyEpoch: number; sealedKey: string; signature: string }[];
  rosters: { name: string; signer: string; previous: string | null; version: number; keyEpoch: number; members: Member[]; rogue: boolean; json: string; hash: string }[];
  commitments: { keyEpoch: number; commitment: string }[];
  chains: ({ vault: string; trusted: string | null; newer: string[]; latest: string } & Outcome)[];
  heads: ({ vault: string; remembered: string | null; latest: string | null } & Outcome)[];
  memberDiffs: { roster: string; members: Member[]; expected: core.MemberDiff }[];
  rosterRoles: { roster: string; identity: [string, boolean]; member: string | null; signer: string | null }[];
  keyPins: core.KeyPins;
  pinChecks: { identity: [string, boolean]; email: string | null; expected: string }[];
  reviews: { name: string; previous: string | null; signer: string; members: Member[]; expected: core.RosterReview }[];
  epochChecks: { pinned: core.EpochPin | null; current: core.EpochPin; expected: string }[];
  keyPinsWithEpoch: core.KeyPins;
  pinsEpochChecks: { current: core.EpochPin; rosterVersion: number | null; expected: string }[];
  keyPinsRaised: core.KeyPins;
  mergedEpochs: Record<string, core.EpochPin>;
  keyPinsLeft: core.KeyPins;
  keyPinsGrandfathered: core.KeyPins;
  keyPinsWithheld: core.KeyPins;
  keyPinsUnsigned: core.KeyPins;
  keyPinsRosterMax: core.KeyPins;
  keyPinsOwn: core.KeyPins;
  observations: { observation: core.VaultObservation; expected: core.Observed; accept?: boolean; accepted?: core.KeyPins }[];
  emails: { email: string; expected: string }[];
  admissions: { pins: string; observation: core.VaultObservation; expected: core.Admission }[];
  accepts: ({ pins: string; observation: core.VaultObservation } & Outcome)[];
  merges: ({ name: string; base: core.KeyPins; ours: core.KeyPins } & Outcome)[];
  mergesLastKnown: ({ name: string; base: core.KeyPins; lastKnown: core.KeyPins } & Outcome)[];
  declines: { pins: string; vaultId: string; currentRow: boolean; expected: core.KeyPins }[];
  keyPinsBound: core.KeyPins;
  legacyWraps: { pins: string; keyEpoch: number; expected: boolean }[];
  ownIdentity: { hash: string; pins: core.KeyPins; checks: { pins: string; listed: string | null; expected: string }[] };
}

const files = import.meta.glob("../../testdata/vectors.json", { eager: true, import: "default" });
const V = (Object.values(files)[0] as { signedSharing: SharingVectors }).signedSharing;
const VID = V.vault.id;

const accountOf = (name: string) => {
  const a = V.accounts.find((x) => x.name === name)!;
  return core.accountFromSessionBytes(a.id, fromB64u(a.sessionBytes));
};
const ident = (name: string) => V.identities.find((x) => x.name === name)!;
const who = (name: string, legacy = false) => (legacy ? ident(name).legacyIdentity : ident(name).publicIdentity);
const rosterJson = (name: string) => V.rosters.find((r) => r.name === name)!.json;
/** A thrown core error's code (its message). */
const codeOf = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return "no error";
};
/** A case's `expected`, or its `error`, as the vectors give them (descriptions end in "…": compared by prefix). */
function outcome(c: Outcome, run: () => unknown) {
  if (c.error !== undefined) {
    const got = codeOf(run);
    if (c.error.endsWith("…")) expect(got.startsWith(c.error.slice(0, -1)), `${JSON.stringify(c)} → ${got}`).toBe(true);
    else expect(got, JSON.stringify(c)).toBe(c.error);
  } else expect(run(), JSON.stringify(c)).toStrictEqual(c.expected);
}
const inputs = (members: Member[], withEmail = true): core.RosterMemberInput[] =>
  members.map(([name, role, legacy, email]) => ({ ...who(name, !!legacy), role, ...(withEmail && typeof email === "string" ? { email } : {}) }));
const signers = () => Object.fromEntries(V.accounts.map((a) => [a.name, accountOf(a.name).openSigningIdentity(a.record)]));
/** Alice's vault key (the vectors' own), from its epoch-bound wrap. */
const aliceKey = (wrap: "wrappedKeyV2" | "secondKeyV2" = "wrappedKeyV2") => accountOf("alice").openVaultKey(VID, V.vault[wrap], "account", 0, false);

test("signedSharing vectors: identities, records, fingerprints, a forged upgrade, key openings and key ids", () => {
  expect(V, "testdata/vectors.json signedSharing").toBeDefined();
  for (const a of V.accounts) {
    const acct = accountOf(a.name);
    const signer = acct.openSigningIdentity(a.record);
    const i = ident(a.name);
    expect(signer.publicIdentity(), a.name).toStrictEqual(i.publicIdentity);
    expect(acct.legacyIdentity(), a.name).toStrictEqual(i.legacyIdentity);
    expect(acct.legacyIdentity().user_id).toBe(a.id);
    expect(signer.fingerprint(), a.name).toBe(i.fingerprint);
    expect(signer.identityHash(), a.name).toBe(i.hash);
    expect(core.verifyIdentity(i.publicIdentity)).toStrictEqual({ user_id: a.id, signing: true, hash: i.hash, legacy_hash: i.legacyHash, fingerprint: i.fingerprint });
    expect(core.verifyIdentity(i.legacyIdentity).hash).toBe(i.legacyHash);
    // Another account's record doesn't open (the server can't hand someone else's identity to this account).
    const other = V.accounts.find((x) => x.name !== a.name)!;
    expect(codeOf(() => acct.openSigningIdentity(other.record))).not.toBe("no error");
    signer.free();
    acct.free();
  }
  // Someone else's Ed25519 key paired with Bob's X25519 key: no X25519 cross-signature, so it doesn't verify (review H1).
  expect(codeOf(() => core.verifyIdentity(V.forgedUpgrade))).toBe("bad_signature");
  // Without the X25519 signature, a full identity doesn't verify either.
  expect(codeOf(() => core.verifyIdentity({ ...who("bob"), x25519_signature: null }))).not.toBe("no error");
  const alice = accountOf("alice");
  for (const c of V.openings) {
    outcome(c, () => {
      const k = alice.openVaultKey(VID, V.vault[c.wrap], "account", c.keyEpoch, c.legacyAllowed);
      const id = k.keyId(VID);
      k.free();
      return id;
    });
  }
  const first = aliceKey();
  const second = aliceKey("secondKeyV2");
  expect([first.keyId(VID), second.keyId(VID)]).toStrictEqual([V.keyIds.first, V.keyIds.second]);
  expect(first.epochPin(VID, 3)).toStrictEqual({ key_epoch: 3, key_id: V.keyIds.first, retired: [], signed_since: null });
  first.free();
  second.free();
});

test("signedSharing vectors: share signatures verify byte for byte, and any change fails with bad_signature", () => {
  for (const s of V.shares) {
    const to = who(s.recipient, s.recipientLegacy);
    const signer = who(s.signer);
    expect(core.verifyShare(s.vaultId, to, s.role, s.keyEpoch, s.sealedKey, signer, s.signature).hash).toBe(ident(s.signer).hash);
    // A share to the legacy identity verifies for the account with a signing key too.
    if (s.recipientLegacy) core.verifyShare(s.vaultId, who(s.recipient), s.role, s.keyEpoch, s.sealedKey, signer, s.signature);
    expect(codeOf(() => core.verifyShare(s.vaultId, to, s.role === "read" ? "write" : "read", s.keyEpoch, s.sealedKey, signer, s.signature))).toBe("bad_signature");
    expect(codeOf(() => core.verifyShare(s.vaultId, to, s.role, s.keyEpoch, `${s.sealedKey}x`, signer, s.signature))).toBe("bad_signature");
    const other = V.identities.find((x) => x.name !== s.signer)!.publicIdentity;
    expect(codeOf(() => core.verifyShare(s.vaultId, to, s.role, s.keyEpoch, s.sealedKey, other, s.signature))).toBe("bad_signature");
  }
  const all = signers();
  for (const s of V.shares) expect(all[s.signer]!.signShare(s.vaultId, who(s.recipient, s.recipientLegacy), s.role, s.keyEpoch, s.sealedKey)).toBe(s.signature);
  for (const s of Object.values(all)) s.free();
});

test("signedSharing vectors: rosters (signed again through the review), commitments, chains, heads, member comparisons and roles", () => {
  const key = aliceKey();
  const all = signers();
  for (const r of V.rosters) {
    if (r.rogue) continue;
    const previous = r.previous ? rosterJson(r.previous) : null;
    const members = inputs(r.members);
    const review = core.rosterReview(VID, previous, all[r.signer]!.publicIdentity(), members, null);
    expect(all[r.signer]!.signRoster(key, VID, previous, r.keyEpoch, members, review.digest), r.name).toBe(r.json);
    expect(key.matchesRoster(VID, r.json), r.name).toBe(true);
    // Another vault's id: not this vault's roster (review L1).
    expect(key.matchesRoster("00000000-0000-4000-8000-0000000000f2", r.json), r.name).toBe(false);
    // Another list than the one reviewed is never signed.
    expect(codeOf(() => all[r.signer]!.signRoster(key, VID, previous, r.keyEpoch, members.slice(0, 1), review.digest))).not.toBe("no error");
  }
  for (const r of V.rosters) expect(core.rosterHash(r.json), r.name).toBe(r.hash);
  for (const c of V.commitments) expect(key.commitment(VID, c.keyEpoch)).toBe(c.commitment);
  const named = (json: string) => V.rosters.find((r) => r.json === json)?.name ?? json;
  for (const c of V.chains) outcome(c, () => named(core.verifyRosterChain(c.vault, c.trusted ? rosterJson(c.trusted) : null, c.newer.map(rosterJson), rosterJson(c.latest))));
  for (const h of V.heads) outcome(h, () => core.rosterHead(h.vault, h.remembered ? rosterJson(h.remembered) : null, h.latest ? rosterJson(h.latest) : null));
  for (const d of V.memberDiffs) expect(core.compareMembers(rosterJson(d.roster), inputs(d.members, false))).toStrictEqual(d.expected);
  for (const r of V.rosterRoles) {
    const id = who(r.identity[0], r.identity[1]);
    expect(core.rosterMemberRole(rosterJson(r.roster), id) ?? null, JSON.stringify(r)).toBe(r.member);
    expect(core.rosterSignerRole(rosterJson(r.roster), id) ?? null, JSON.stringify(r)).toBe(r.signer);
  }
  for (const s of Object.values(all)) s.free();
  key.free();
});

test("signedSharing vectors: key pins, pin checks, reviews, epochs, tombstones, grandfathering, admissions and own identity", () => {
  let pins = core.pinSet(null, who("bob"), "bob@example.com", true, 1000);
  pins = core.pinSet(pins, who("carol", true), "carol@example.com", false, 1000);
  expect(pins).toStrictEqual(V.keyPins);
  for (const c of V.pinChecks) expect(core.pinCheck(V.keyPins, who(c.identity[0], c.identity[1]), c.email), JSON.stringify(c)).toBe(c.expected);
  expect(codeOf(() => core.pinCheck(V.keyPins, { ...who("carol"), user_id: who("bob").user_id }, null))).toBe("bad_signature");
  const all = signers();
  for (const c of V.reviews) {
    const previous = c.previous ? rosterJson(c.previous) : null;
    expect(core.rosterReview(VID, previous, all[c.signer]!.publicIdentity(), inputs(c.members), V.keyPins), c.name).toStrictEqual(c.expected);
  }
  for (const s of Object.values(all)) s.free();
  for (const c of V.epochChecks) expect(core.epochCheck(c.pinned, c.current), JSON.stringify(c)).toBe(c.expected);
  const key = aliceKey();
  const second = aliceKey("secondKeyV2");
  // Round 5: a key this device gave the vault itself is pinned with `pinsRecordRotation` (a roster version only with its hash).
  const hashOf = (name: string) => V.rosters.find((r) => r.name === name)!.hash;
  const record = (p: core.KeyPins | null, current: core.EpochPin, rosterVersion: number | null = null, roster: string | null = null) =>
    core.pinsRecordRotation(p, VID, "sealed", current, rosterVersion, roster ? hashOf(roster) : null);
  const withEpoch = record(V.keyPins, key.epochPin(VID, 1), 2, "v2");
  expect(withEpoch).toStrictEqual(V.keyPinsWithEpoch);
  expect(codeOf(() => record(withEpoch, key.epochPin(VID, 0), 2, "v2"))).toBe("rollback");
  // A roster version without its hash (or a hash without its version) throws.
  expect(codeOf(() => record(withEpoch, second.epochPin(VID, 2), 3))).not.toBe("no error");
  expect(codeOf(() => core.pinsRecordRotation(withEpoch, VID, "sealed", second.epochPin(VID, 2), null, hashOf("v3")))).not.toBe("no error");
  for (const c of V.pinsEpochChecks) expect(core.pinsEpochCheck(withEpoch, VID, c.current, c.rosterVersion), JSON.stringify(c)).toBe(c.expected);
  const raised = record(withEpoch, second.epochPin(VID, 2), 3, "v3");
  expect(raised).toStrictEqual(V.keyPinsRaised);
  expect(core.mergePins(withEpoch, record(null, second.epochPin(VID, 2))).epochs).toStrictEqual(V.mergedEpochs);
  const left = core.pinsLeave(raised, VID, 3, 2000);
  expect(left).toStrictEqual(V.keyPinsLeft);
  // Round 5: each grandfathered vault with the key id it has now (only that key is covered).
  const candidates = [{ vault_id: VID, key_id: V.keyIds.first }];
  const grandfathered = core.pinsGrandfather(V.keyPins, candidates, true);
  expect(grandfathered).toStrictEqual(V.keyPinsGrandfathered);
  expect(grandfathered.grandfathered?.[VID]).toBe(V.keyIds.first);
  // Set once: a second call changes nothing.
  expect(core.pinsGrandfather(grandfathered, [{ vault_id: "00000000-0000-4000-8000-0000000000f2", key_id: V.keyIds.second }], true)).toStrictEqual(grandfathered);
  // A bare vault id (the format from before round 5) is refused.
  expect(codeOf(() => core.pinsGrandfather(V.keyPins, [VID] as unknown as core.GrandfatherCandidate[], true))).not.toBe("no error");
  // Trust memory missing (the identity wasn't created by this unlock): an empty list.
  const withheld = core.pinsGrandfather(V.keyPins, candidates, false);
  expect(withheld).toStrictEqual(V.keyPinsWithheld);
  const unsigned = record(grandfathered, key.epochPin(VID, 1));
  expect(unsigned).toStrictEqual(V.keyPinsUnsigned);
  const rosterMax = core.pinsObserve(withEpoch, {
    vault_id: VID,
    key_kind: "sealed",
    key: key.epochPin(VID, 1),
    roster_version: 3,
    roster_hash: V.rosters.find((r) => r.name === "v3")!.hash,
    signed_share: true,
    paused: false,
  }).pins;
  expect(rosterMax).toStrictEqual(V.keyPinsRosterMax);
  // An own (account-wrapped) vault observed: its pin is marked `own` (round 4).
  const own = core.pinsObserve(null, { vault_id: VID, key_kind: "account", key: key.epochPin(VID, 1), roster_version: null, roster_hash: null, signed_share: false, paused: false }).pins;
  expect(own).toStrictEqual(V.keyPinsOwn);
  const sets: Record<string, core.KeyPins | null> = { none: null, withEpoch, raised, left, grandfathered, withheld, unsigned, rosterMax, own };
  // Admissions, also with `chain_hashes` (a chain fetched now) and the `own` mark.
  expect(V.admissions.some((c) => c.observation.chain_hashes)).toBe(true);
  for (const c of V.admissions) expect(core.pinsAdmit(sets[c.pins], c.observation), JSON.stringify(c)).toStrictEqual(c.expected);
  // Accepts (consents and invitations) go through `pinsAccept`: what it pins, or the refusal it throws.
  for (const c of V.accepts) outcome(c, () => core.pinsAccept(sets[c.pins], c.observation));
  // Merges are monotone: retired key ids never shrink, a tombstone absorbs the pins it beats, a re-join beats its tombstone.
  for (const c of V.merges) outcome(c, () => core.mergePins(c.base, c.ours));
  // Round 5 M1: a device's last-known copy merged into a newer server copy (person pins of another identity: the server's).
  expect(V.mergesLastKnown.length).toBeGreaterThan(0);
  for (const c of V.mergesLastKnown) outcome(c, () => core.pinsMergeLastKnown(c.base, c.lastKnown));
  // Round 5 M2: a decline never gives up a held vault or one listed now, and never takes a server's roster version.
  expect(V.declines.length).toBeGreaterThan(0);
  for (const c of V.declines) expect(core.pinsDecline(sets[c.pins], c.vaultId, c.currentRow, 3000), JSON.stringify([c.pins, c.currentRow])).toStrictEqual(c.expected);
  let step: core.KeyPins = grandfathered;
  for (const c of V.observations) {
    const observed = core.pinsObserve(step, c.observation);
    expect(observed, JSON.stringify(c.observation)).toStrictEqual(c.expected);
    // Round 5: a first signature needs the user's OK (`first_signed`); the vectors accept it with `pinsAccept`.
    step = c.accept ? core.pinsAccept(step, c.observation) : observed.pins;
    if (c.accept) expect(step).toStrictEqual(c.accepted);
  }
  for (const c of V.emails) expect(core.normalizeEmail(c.email), c.email).toBe(c.expected);
  // Item 7: a v1 (unbound) wrap is refused for an epoch at or below the one this account opened from a bound wrap.
  const withBound: Record<string, core.KeyPins | null> = { ...sets, bound: V.keyPinsBound };
  expect(V.legacyWraps.some((c) => c.pins === "bound" && !c.expected)).toBe(true);
  for (const c of V.legacyWraps) expect(core.pinsLegacyWrapAllowed(withBound[c.pins], VID, c.keyEpoch), JSON.stringify(c)).toBe(c.expected);
  expect(core.pinsSetOwnIdentity(V.keyPins, V.ownIdentity.hash)).toStrictEqual(V.ownIdentity.pins);
  for (const c of V.ownIdentity.checks) expect(core.pinsCheckOwnIdentity(c.pins === "withOwn" ? V.ownIdentity.pins : null, c.listed), JSON.stringify(c)).toBe(c.expected);
  expect(codeOf(() => core.pinsSetOwnIdentity(V.ownIdentity.pins, ident("bob").hash))).toBe("identity_mismatch");
  // Sealed key pins open only for the version they were sealed as, and only for their account.
  const bob = accountOf("bob");
  const sealed = bob.sealKeyPins(V.keyPins, 3);
  expect(bob.openKeyPins(sealed, 3).pins).toStrictEqual(V.keyPins.pins);
  expect(codeOf(() => bob.openKeyPins(sealed, 2))).toBe("rollback");
  expect(codeOf(() => accountOf("alice").openKeyPins(sealed, 3))).not.toBe("no error");
  key.free();
  second.free();
});

// ------------------------------------------------------------------ checkVault

const OTHER = "00000000-0000-4000-8000-0000000000f2";

/** Alice's vault (the vectors' own), shared with Bob: keys, shares, rosters and Bob's rows. */
function world() {
  const alice = accountOf("alice");
  const bob = accountOf("bob");
  const aliceSigner = alice.openSigningIdentity(V.accounts[0]!.record);
  const bobSigner = bob.openSigningIdentity(V.accounts[1]!.record);
  const key = aliceKey();
  const share = (role: string, epoch = 0, to = bobSigner.publicIdentity(), k = key) => aliceSigner.sealAndSignShare(k, VID, to, role, epoch);
  const snapshot = (s: core.PublicIdentity, email: string, name = email.split("@")[0]!) => ({
    ...s,
    email,
    name,
    signing_key: s.signing_key ?? null,
    identity_signature: s.identity_signature ?? null,
    x25519_signature: s.x25519_signature ?? null,
  });
  const signerSnap = snapshot(aliceSigner.publicIdentity(), "alice@example.com", "Alice");
  /** A roster signed by Alice (through the review, as the apps sign). */
  const roster = (previous: string | null, epoch: number, bobRole = "write", k = key, vaultId = VID, bobIdentity = bobSigner.publicIdentity()) => {
    const members = [
      { ...aliceSigner.publicIdentity(), role: "owner" },
      { ...bobIdentity, role: bobRole },
    ];
    const review = core.rosterReview(vaultId, previous, aliceSigner.publicIdentity(), members, null);
    return aliceSigner.signRoster(k, vaultId, previous, epoch, members, review.digest);
  };
  const v1 = roster(null, 0);
  /** Bob's pins after he accepted the vault at epoch 0 with roster v1. */
  const accepted = (pins: core.KeyPins | null = null) => core.pinsRecordRotation(pins, VID, "sealed", key.epochPin(VID, 0), 1, core.rosterHash(v1));
  return { alice, bob, aliceSigner, bobSigner, key, share, signerSnap, roster, snapshot, v1, accepted };
}
type World = ReturnType<typeof world>;

/** Bob's pins with Alice's vault grandfathered at the key it has (round 5: bound to its key id). */
const grandfatheredFor = (w: World) => core.pinsGrandfather(null, [{ vault_id: VID, key_id: w.key.keyId(VID) }], true);

const sealedRow = (wrapped: string, role: string, epoch: number | undefined, share: unknown, roster: string | null = null): import("../src/background/signed-sharing").SignedVaultRow => ({
  id: VID,
  meta: "",
  role: role as "write",
  wrapped_key: wrapped,
  key_kind: "sealed",
  key_epoch: epoch as number,
  share,
  member_roster: roster,
  member_roster_seq: roster ? 1 : 0,
});

/** Bob's row for Alice's signed share at `epoch` with `role`, and its roster (v1 by default). */
function signedRow(w: World, role = "write", over: { epoch?: number; roster?: string | null; signer?: unknown } = {}) {
  const s = w.share(role, over.epoch ?? 0);
  return sealedRow(s.sealed_key, role, over.epoch ?? 0, { signature: s.signature, signer: over.signer ?? w.signerSnap, signer_deleted: false }, over.roster === undefined ? w.v1 : over.roster);
}

async function check(w: World, row: ReturnType<typeof sealedRow>, over: Partial<Parameters<typeof ss.checkVault>[0]> = {}) {
  const key = w.bob.openVaultKey(row.id, row.wrapped_key, row.key_kind, row.key_epoch ?? 0, true);
  try {
    return await ss.checkVault({
      row,
      key,
      me: w.bobSigner.publicIdentity(),
      pins: w.accepted(),
      remembered: null,
      seenSigned: false,
      paused: false,
      fetchRosters: async (after) => [w.v1].slice(after),
      now: 2000,
      ...over,
    });
  } finally {
    key.free();
  }
}

const why = (r: { trust: import("../src/background/signed-sharing").Trust }) => (r.trust.state === "refused" ? r.trust.why : r.trust.state);
/** The consent token a waiting verdict carries ("" for anything else). */
const tokenOf = (r: { trust: import("../src/background/signed-sharing").Trust }) => (r.trust.state === "waiting" ? r.trust.token : "");

test("checkVault: a signed share of an accepted vault verifies; the signer is pinned (first seen), the epoch kept, the roster remembered", async () => {
  const w = world();
  const r = await check(w, signedRow(w));
  expect(r.trust).toMatchObject({ state: "ok", signer: { email: "alice@example.com", pinned: false, firstSeen: true, verified: false, fingerprint: ident("alice").fingerprint } });
  expect(r.signed).toBe(true);
  expect(r.roster).toBe(w.v1);
  expect(core.pinCheck(r.pins, w.aliceSigner.publicIdentity(), "alice@example.com")).toBe("match");
  expect(r.pins?.epochs?.[VID]).toMatchObject({ key_epoch: 0, key_id: w.key.keyId(VID), retired: [], signed_since: 1, roster_version_max: 1, roster_hash: core.rosterHash(w.v1) });
});

test("H3: a sealed vault the account never accepted (planted by the server) isn't used: it waits for consent, and nothing is pinned", async () => {
  const w = world();
  // Signed, by a stranger the server controls (Carol), with a roster of her own: waiting, with her fingerprint.
  const carolAcct = accountOf("carol");
  const carol = carolAcct.openSigningIdentity(V.accounts[2]!.record);
  const own = carolAcct.newVaultKey(VID);
  const ck = own.takeKey();
  const s = carol.sealAndSignShare(ck, VID, w.bobSigner.publicIdentity(), "write", 0);
  const members = [
    { ...carol.publicIdentity(), role: "owner" },
    { ...w.bobSigner.publicIdentity(), role: "write" },
  ];
  const r1 = carol.signRoster(ck, VID, null, 0, members, core.rosterReview(VID, null, carol.publicIdentity(), members, null).digest);
  const row = {
    ...sealedRow(s.sealed_key, "write", 0, { signature: s.signature, signer: w.snapshot(carol.publicIdentity(), "carol@example.com"), signer_deleted: false }, r1),
    meta: ck.encryptMeta(VID, { name: "Payroll‮" }),
  };
  const r = await check(w, row, { pins: null, fetchRosters: async () => [r1] });
  expect(r.trust).toMatchObject({ state: "waiting", name: "Payroll", acceptable: true, rejoin: false, signer: { email: "carol@example.com", fingerprint: ident("carol").fingerprint, pinned: false } });
  expect(r.pins).toBe(null);
  expect(r.roster).toBe(null);
  expect(r.signed).toBe(false);
  // Accepting anything but the token of what was shown changes nothing (a fingerprint alone isn't it); the token pins key, signer and roster.
  expect(tokenOf(r)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect((await check(w, row, { pins: null, fetchRosters: async () => [r1], accept: ident("carol").fingerprint })).trust.state).toBe("waiting");
  const ok = await check(w, row, { pins: null, fetchRosters: async () => [r1], accept: tokenOf(r) });
  expect(ok.trust.state).toBe("ok");
  expect(ok.roster).toBe(r1);
  expect(ok.pins?.epochs?.[VID]?.signed_since).toBe(1);
  expect(core.pinCheck(ok.pins, carol.publicIdentity(), "carol@example.com")).toBe("match");
  // Unsigned and never accepted: waiting, and it can't be accepted (Decline only).
  const unsigned = await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null), { pins: null });
  expect(unsigned.trust).toMatchObject({ state: "waiting", acceptable: false });
  expect((await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null), { pins: null, accept: "x" })).trust.state).toBe("waiting");
  // Grandfathered at the first signed sync: an unsigned share from before stays usable, "Not yet signed".
  expect((await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null), { pins: grandfatheredFor(w) })).trust).toStrictEqual({ state: "unsigned" });
  ck.free();
  carol.free();
});

test("H1: an identity pairing someone's X25519 key with another signing key is refused; a known email under a new account stops (email_conflict)", async () => {
  const w = world();
  const row = signedRow(w, "write", { signer: w.snapshot(V.forgedUpgrade, "bob@example.com") });
  expect(why(await check(w, row))).toBe("bad_signature");
  // Alice is pinned; Carol's account presents itself with Alice's email.
  const pins = core.pinSet(w.accepted(), w.aliceSigner.publicIdentity(), "alice@example.com", true, 1000);
  const r = await check(w, signedRow(w, "write", { signer: w.snapshot(who("carol"), " Alice@Example.com") }), { pins });
  expect(r.trust).toMatchObject({ state: "refused", why: "email_conflict", changed: { kind: "email_conflict", userId: who("carol").user_id, fingerprint: ident("carol").fingerprint } });
  expect(r.pins).toBe(pins);
});

test("H4: epochs and key ids: an older key, a retired key or an old key relabelled with a higher epoch is refused; a missing epoch too", async () => {
  const w = world();
  // Bob accepted the vault at epoch 1 with Alice's second key (a key replacement); the server serves the first key at epoch 0.
  const second = aliceKey("secondKeyV2");
  const pins = core.pinsRecordRotation(null, VID, "sealed", second.epochPin(VID, 1), null, null);
  expect(why(await check(w, signedRow(w), { pins }))).toBe("older");
  // The first key relabelled as epoch 2 (signed by Alice at epoch 2, a roster chain v1 → v2 at epoch 2): its key id is retired.
  const v2 = w.roster(w.v1, 2);
  const raised = core.pinsRecordRotation(w.accepted(), VID, "sealed", second.epochPin(VID, 1), 2, core.rosterHash(v2));
  expect(why(await check(w, signedRow(w, "write", { epoch: 2, roster: v2 }), { pins: raised, fetchRosters: async () => [w.v1, v2] }))).toBe("older");
  // The same key at a higher epoch than pinned (never replaced): conflict.
  expect(why(await check(w, signedRow(w, "write", { epoch: 2, roster: v2 }), { fetchRosters: async () => [w.v1, v2] }))).toBe("conflict");
  // No key epoch at all.
  const s = w.share("write");
  expect(why(await check(w, sealedRow(s.sealed_key, "write", undefined, { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, w.v1)))).toBe("missing_epoch");
  expect(ss.refusedUnopened("missing_epoch")).toMatchObject({ state: "refused", why: "missing_epoch" });
  second.free();
});

test("round 3: an unsigned key replacement on an accepted vault waits (replaced); accepting the key shown pins it", async () => {
  const w = world();
  const second = aliceKey("secondKeyV2");
  // Bob had the vault from before (grandfathered, unsigned) at epoch 0; an app that doesn't sign replaced the key.
  const pins = core.pinsRecordRotation(grandfatheredFor(w), VID, "sealed", w.key.epochPin(VID, 0), null, null);
  const row = sealedRow(second.shareTo(VID, who("bob").public_key), "write", 1, null);
  const r = await check(w, row, { pins });
  expect(r.trust).toMatchObject({ state: "waiting", replaced: true, acceptable: true });
  expect(r.pins).toBe(pins);
  expect((await check(w, row, { pins, accept: second.keyId(VID) })).trust.state).toBe("waiting");
  const ok = await check(w, row, { pins, accept: tokenOf(r) });
  expect(ok.trust).toStrictEqual({ state: "unsigned" });
  expect(ok.pins?.epochs?.[VID]).toMatchObject({ key_epoch: 1, key_id: second.keyId(VID) });
  second.free();
});

test("round 3: trust memory missing: an unsigned vault waits and may be accepted (the key shown); otherwise it can't", async () => {
  const w = world();
  const row = sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null);
  const withheld = core.pinsGrandfather(null, [{ vault_id: VID, key_id: w.key.keyId(VID) }], false);
  expect((await check(w, row, { pins: withheld })).trust).toMatchObject({ state: "waiting", acceptable: false, token: "" });
  const r = await check(w, row, { pins: withheld, memoryMissing: true });
  expect(r.trust).toMatchObject({ state: "waiting", acceptable: true });
  expect((await check(w, row, { pins: withheld, memoryMissing: true, accept: tokenOf(r) })).trust).toStrictEqual({ state: "unsigned" });
});

test("round 3: a roster older than the highest the account trusted, or another roster at that version, is refused (new device too)", async () => {
  const w = world();
  const v2 = w.roster(w.v1, 0, "read");
  const seen = core.pinsObserve(w.accepted(), {
    vault_id: VID,
    key_kind: "sealed",
    key: w.key.epochPin(VID, 0),
    roster_version: 2,
    roster_hash: core.rosterHash(v2),
    signed_share: true,
    paused: false,
  }).pins;
  // A device with no roster memory is shown v1 again.
  expect(why(await check(w, signedRow(w), { pins: seen }))).toBe("downgraded");
  // Another v2 (a fork) at the same version.
  const fork = w.roster(w.v1, 0, "admin");
  const s = w.share("admin");
  const forked = sealedRow(s.sealed_key, "admin", 0, { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, fork);
  expect(why(await check(w, forked, { pins: seen, fetchRosters: async () => [w.v1, fork] }))).toBe("roster_forked");
});

test("round 3: emails show in the normalizeEmail form (an internationalized domain in punycode)", async () => {
  expect(ss.showEmail(" Erin@Bücher.example\u200b")).toBe("erin@xn--bcher-kva.example");
  const w = world();
  const r = await check(w, signedRow(w, "write", { signer: w.snapshot(w.aliceSigner.publicIdentity(), "ALICE@Bücher.example") }));
  expect(r.trust).toMatchObject({ state: "ok", signer: { email: "alice@xn--bcher-kva.example" } });
});

test("downgrades: a signed share without its roster, an unsigned share where a roster is trusted or the vault was seen signed, are refused", async () => {
  const w = world();
  expect(why(await check(w, signedRow(w, "write", { roster: null })))).toBe("downgraded");
  const unsigned = sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null, w.v1);
  expect(why(await check(w, unsigned))).toBe("downgraded");
  // The account's pins say signed since v1, and the server drops both share and roster.
  expect(why(await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null)))).toBe("downgraded");
  // This browser saw it signed (even with pins that don't know it).
  expect(why(await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null), { pins: grandfatheredFor(w), seenSigned: true }))).toBe("downgraded");
});

test("L5/L6: the trusted roster must list this account with the row's role; the signer must be an owner or admin listed with their full identity", async () => {
  const w = world();
  // Alice signed an admin share, but her roster lists Bob as a writer: the server raised the role.
  expect(why(await check(w, signedRow(w, "admin")))).toBe("not_listed");
  // A share signed by Bob himself (a writer in the roster).
  const s = w.share("write");
  const byBob = w.bobSigner.signShare(VID, w.bobSigner.publicIdentity(), "write", 0, s.sealed_key);
  const row = sealedRow(s.sealed_key, "write", 0, { signature: byBob, signer: w.snapshot(w.bobSigner.publicIdentity(), "bob@example.com"), signer_deleted: false }, w.v1);
  expect(why(await check(w, row))).toBe("signer_not_manager");
  // A refusal after the signer's checks pins nothing.
  const r = await check(w, signedRow(w, "admin"), { pins: null });
  expect(r.pins).toBe(null);
  expect(r.roster).toBe(null);
});

test("L1 and the chain: another vault's roster, a fork, a rollback or a roster the server doesn't serve are refused; newer versions after the row's are ignored", async () => {
  const w = world();
  const foreign = w.roster(null, 0, "write", w.key, OTHER);
  expect(why(await check(w, signedRow(w, "write", { roster: foreign }), { fetchRosters: async () => [foreign] }))).not.toBe("ok");
  const v2 = w.roster(w.v1, 0, "read");
  // The server already has v2 but the row names v1: the chain ends exactly at v1.
  expect(why(await check(w, signedRow(w), { fetchRosters: async () => [w.v1, v2] }))).toBe("ok");
  expect(why(await check(w, signedRow(w), { remembered: v2 }))).toBe("rollback");
  expect(why(await check(w, signedRow(w, "write", { roster: null }), { remembered: w.v1 }))).toBe("rollback");
  const fork = w.roster(null, 0, "admin");
  expect(why(await check(w, signedRow(w, "write", { roster: fork }), { remembered: w.v1 }))).toBe("roster_forked");
  expect(why(await check(w, signedRow(w, "read", { roster: v2 }), { fetchRosters: async () => [w.v1] }))).toBe("roster not served");
  // Remembered and unchanged: no fetch at all.
  expect(why(await check(w, signedRow(w), { remembered: w.v1, fetchRosters: async () => Promise.reject(new Error("offline")) }))).toBe("ok");
  // Offline while a new roster needs checking: refused for now, with its own words.
  expect((await check(w, signedRow(w), { fetchRosters: async () => Promise.reject(new Error("offline")) })).trust).toMatchObject({ state: "refused", reason: ss.CHECK_LATER_TEXT });
});

test("M2: roster fetching stops at 1000 versions, 16 MiB or 10 pages; the vault is refused rather than a partial chain trusted", async () => {
  const pageOf =
    (n: number, size = 1, more = true) =>
    async () => ({ rosters: Array.from({ length: n }, () => "x".repeat(size)), more });
  await expect(ss.collectRosters(0, pageOf(100))).rejects.toBeInstanceOf(ss.TooManyRosters);
  await expect(ss.collectRosters(0, pageOf(1001, 1, false))).rejects.toBeInstanceOf(ss.TooManyRosters);
  await expect(ss.collectRosters(0, pageOf(2, 9 * 1024 * 1024, false))).rejects.toBeInstanceOf(ss.TooManyRosters);
  const asked: number[] = [];
  expect(
    await ss.collectRosters(5, async (after) => {
      asked.push(after);
      return { rosters: after < 9 ? ["a", "b"] : [], more: after < 9 };
    }),
  ).toStrictEqual(["a", "b", "a", "b"]);
  expect(asked).toStrictEqual([5, 7, 9]);
  const w = world();
  expect((await check(w, signedRow(w), { fetchRosters: () => Promise.reject(new ss.TooManyRosters()) })).trust).toMatchObject({ state: "refused", reason: ss.TOO_MANY_TEXT });
});

test("M3: names and emails from the server are cleaned; the pinned email comes first, the server's only as 'listed by your server as'; 'verified' only with a pinned email", async () => {
  expect(ss.cleanText("  Al\u0000ice​ \n‮Evil  ")).toBe("Al ice Evil");
  expect(ss.cleanText("x".repeat(300))).toHaveLength(128);
  expect(ss.cleanText(42)).toBe("");
  const w = world();
  const pins = core.pinSet(w.accepted(), w.aliceSigner.publicIdentity(), "alice@example.com", true, 1000);
  const r = await check(w, signedRow(w, "write", { signer: w.snapshot(w.aliceSigner.publicIdentity(), "ceo@evil.example‮", "The CEO") }), { pins });
  expect(r.trust).toMatchObject({ state: "ok", signer: { email: "alice@example.com", pinned: true, listedAs: "ceo@evil.example", verified: true, firstSeen: false } });
  // First seen: the server's email, not pinned, never verified.
  const first = await check(w, signedRow(w, "write", { signer: w.snapshot(w.aliceSigner.publicIdentity(), "alice@example.com", "Alice\u0007") }));
  expect(first.trust).toMatchObject({ state: "ok", signer: { email: "alice@example.com", pinned: false, listedAs: "Alice", verified: false } });
});

test("paused: every shared vault is refused (signed or not); own vaults stay", async () => {
  const w = world();
  expect((await check(w, signedRow(w), { paused: true })).trust).toMatchObject({ state: "refused", reason: ss.PAUSED_TEXT });
  expect(why(await check(w, sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null), { paused: true, pins: grandfatheredFor(w) }))).toBe("paused");
});

test("a pinned person's changed key stops the vault; trusting it (pinned again) makes it verify, marked verified", async () => {
  const w = world();
  let pins = core.pinSet(w.accepted(), { ...who("alice", true), public_key: who("carol").public_key }, "alice@example.com", true, 1000);
  const r = await check(w, signedRow(w), { pins });
  expect(r.trust).toMatchObject({
    state: "refused",
    reason: ss.changedText("alice@example.com"),
    changed: { kind: "changed", userId: who("alice").user_id, email: "alice@example.com", fingerprint: ident("alice").fingerprint },
  });
  pins = core.pinSet(pins, w.aliceSigner.publicIdentity(), "alice@example.com", true, 3000);
  expect((await check(w, signedRow(w), { pins })).trust).toMatchObject({ state: "ok", signer: { verified: true, firstSeen: false, pinned: true } });
});

test("trust memory: merged, never overwritten (higher pins version, higher roster per vault, union of signed marks); another account's is never read", () => {
  const w = world();
  const v2 = w.roster(w.v1, 0, "read");
  const stored = { ...ss.emptyMemory("u"), pinsSeq: 5, pinsSealed: "sealed-5", rosters: { [VID]: v2, a: "x" }, signed: [VID] };
  const ours = { ...ss.emptyMemory("u"), pinsSeq: 4, pinsSealed: "sealed-4", rosters: { [VID]: w.v1 }, signed: ["b"] };
  expect(ss.mergeMemory(stored, ours)).toStrictEqual({ userId: "u", pinsSeq: 5, pinsSealed: "sealed-5", pinsDirty: false, rosters: { [VID]: v2, a: "x" }, signed: [VID, "b"] });
  // Our unsent changes on a lower version are merged into the higher one.
  const merged = ss.mergeMemory(stored, { ...ours, pinsDirty: true }, (h) => ({ ...h, pinsSealed: "merged", pinsDirty: true }));
  expect([merged.pinsSeq, merged.pinsSealed, merged.pinsDirty]).toStrictEqual([5, "merged", true]);
  // Ours newer: ours.
  expect(ss.mergeMemory({ ...stored, pinsSeq: 3 }, { ...ours, rosters: { [VID]: v2 } }).rosters[VID]).toBe(v2);
  expect(ss.readMemory(stored, "other")).toBe(null);
  expect(ss.mergeMemory({ ...stored, userId: "other" }, ours)).toBe(ours);
});

test("offline verdict stamps change with whatever the verdict depends on", async () => {
  const w = world();
  const row = signedRow(w);
  const base = { pins: await ss.pinsDigest(w.accepted()), remembered: w.v1, seenSigned: true, paused: false, me: ident("bob").hash };
  const stamp = await ss.contextStamp(row, base);
  expect(await ss.contextStamp(row, { ...base })).toBe(stamp);
  for (const over of [
    { pins: await ss.pinsDigest(core.pinsLeave(w.accepted(), VID, 1, 5)) },
    { pins: await ss.pinsDigest(core.pinSet(w.accepted(), who("dave"), "d@example.com", false, 1)) },
    { remembered: null },
    { seenSigned: false },
    { paused: true },
    { me: ident("bob").legacyHash },
  ]) {
    expect(await ss.contextStamp(row, { ...base, ...over }), JSON.stringify(Object.keys(over))).not.toBe(stamp);
  }
  expect(await ss.contextStamp({ ...row, role: "read" }, base)).not.toBe(stamp);
  // Sealing sets the pins' version: it doesn't count.
  expect(await ss.pinsDigest({ ...w.accepted(), version: 9 })).toBe(base.pins);
});

test("checkInvitation: unsigned invitations can't be accepted; signed ones are checked over this account; nothing is pinned", () => {
  const w = world();
  const s = w.share("write");
  const inv = {
    vault_id: VID,
    role: "write" as const,
    wrapped_key: s.sealed_key,
    meta: "m",
    invited_by: { id: who("alice").user_id, email: "alice@example.com", name: "Alice", public_key: "k" },
    invited_at: 1,
    key_epoch: 0,
  };
  const me = w.bobSigner.publicIdentity();
  // Unsigned: the server's invited_by is only its claim ("listed by your server as").
  expect(ss.checkInvitation({ ...inv, share: null }, me, null, false)).toStrictEqual({ vaultId: VID, state: "unsigned", from: "", listedAs: "alice@example.com" });
  expect(ss.checkInvitation({ ...inv, share: { signature: s.signature, signer: w.signerSnap } }, me, null, false).state).toBe("ok");
  expect(ss.checkInvitation({ ...inv, role: "admin", share: { signature: s.signature, signer: w.signerSnap } }, me, null, false).state).toBe("refused");
  expect(ss.checkInvitation({ ...inv, share: { signature: s.signature, signer: w.signerSnap } }, me, null, true).state).toBe("refused");
  // A known email under another account.
  const pins = core.pinSet(null, who("dave"), "alice@example.com", true, 1);
  expect(ss.checkInvitation({ ...inv, share: { signature: s.signature, signer: w.signerSnap } }, me, pins, false).state).toBe("refused");
  expect(ss.invitationText({ vaultId: "v", state: "unsigned", from: "", listedAs: "alice@example.com" })).toBe(
    "An invitation listed by your server as from alice@example.com isn't signed. Ask the person who shared it to update PassAuth and share again.",
  );
});

test("L1: the consent token binds what was shown (key id and epoch, signer, roster, role); accepting a changed row's old token does nothing", async () => {
  const w = world();
  const withheld = core.pinsGrandfather(null, [], false);
  const row = sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null);
  const shown = await check(w, row, { pins: withheld, memoryMissing: true });
  expect(tokenOf(shown)).not.toBe("");
  // The server changes the row (another role here) before the user's accept arrives.
  const changed = { ...sealedRow(w.key.shareTo(VID, who("bob").public_key), "read", 0, null) };
  const r = await check(w, changed, { pins: withheld, memoryMissing: true, accept: tokenOf(shown) });
  expect(r.trust.state).toBe("waiting");
  expect(tokenOf(r)).not.toBe(tokenOf(shown));
  const base = {
    vaultId: VID,
    role: "write",
    keyId: "k",
    epoch: 0,
    signer: "s",
    email: "alice@example.com",
    pinned: false,
    roster: "r",
    replaced: false,
    rejoin: false,
    own: false,
    firstSigned: false,
  };
  const t = await ss.consentToken(base);
  for (const over of [
    { vaultId: OTHER },
    { role: "read" },
    { keyId: "k2" },
    { epoch: 1 },
    { signer: "s2" },
    { signer: null },
    { roster: "r2" },
    { roster: null },
    { replaced: true },
    { rejoin: true },
    // Round 4 (rule 4): the email shown for the signer, and whether it was the pinned one, are bound too.
    { email: "alice@evil.example" },
    { email: null },
    { pinned: true },
    { own: true },
    // Round 5: a first signature on a vault the account holds is its own kind of consent.
    { firstSigned: true },
  ]) {
    expect(await ss.consentToken({ ...base, ...over }), JSON.stringify(over)).not.toBe(t);
  }
});

test("L2: verdict stamps carry the checks' version (a verdict kept by another version is checked again)", async () => {
  const w = world();
  const row = signedRow(w);
  const base = { pins: await ss.pinsDigest(w.accepted()), remembered: w.v1, seenSigned: true, paused: false, me: ident("bob").hash };
  expect(await ss.contextStamp(row, base, ss.CHECKS_VERSION - 1)).not.toBe(await ss.contextStamp(row, base));
});

test("L8: while sharing is paused, an own (account-wrapped) vault with a roster listing the remembered full identity stays usable", async () => {
  const w = world();
  const fresh = w.bob.newVaultKey(OTHER);
  const k = fresh.takeKey();
  const members = [
    { ...w.bobSigner.publicIdentity(), role: "owner" },
    { ...w.aliceSigner.publicIdentity(), role: "write" },
  ];
  const roster = w.bobSigner.signRoster(k, OTHER, null, 0, members, core.rosterReview(OTHER, null, w.bobSigner.publicIdentity(), members, null).digest);
  const row = { id: OTHER, meta: "", role: "owner" as const, wrapped_key: fresh.wrapped, key_kind: "account" as const, key_epoch: 0, share: null, member_roster: roster, member_roster_seq: 1 };
  const paused = { me: who("bob", true), paused: true, fetchRosters: async () => [roster] };
  expect((await check(w, row, { ...paused, pins: core.pinsSetOwnIdentity(null, ident("bob").hash) })).trust).toStrictEqual({ state: "ok" });
  // Not with another remembered identity, and not for a shared (sealed) row.
  expect(why(await check(w, row, { ...paused, pins: core.pinsSetOwnIdentity(null, ident("carol").hash) }))).toBe("not_listed");
  k.free();
});

test("item 7: an own vault opened from an epoch-bound (v2) wrap is recorded in the pins (bound_since), so a v1 wrap for that epoch is refused from then on; a v1 wrap records nothing", async () => {
  const w = world();
  const ownRow = (wrapped: string, epoch: number) => ({
    id: OTHER,
    meta: "",
    role: "owner" as const,
    wrapped_key: wrapped,
    key_kind: "account" as const,
    key_epoch: epoch,
    share: null,
    member_roster: null,
    member_roster_seq: 0,
  });
  const bound = w.bob.newVaultKeyBound(OTHER, 0);
  expect(core.accountWrapIsBound(bound.wrapped)).toBe(true);
  const r = await check(w, ownRow(bound.wrapped, 0), { fetchRosters: async () => [] });
  expect(r.trust.state === "ok" || r.trust.state === "unsigned", JSON.stringify(r.trust)).toBe(true);
  expect(r.pins?.epochs?.[OTHER]?.bound_since).toBe(0);
  expect(core.pinsLegacyWrapAllowed(r.pins, OTHER, 0)).toBe(false);
  // A later key replacement written v1 by an app while the gate was off still opens.
  expect(core.pinsLegacyWrapAllowed(r.pins, OTHER, 1)).toBe(true);
  // A v1 (unbound) wrap: no mark.
  const legacy = w.bob.newVaultKey(OTHER);
  expect(core.accountWrapIsBound(legacy.wrapped)).toBe(false);
  const r1 = await check(w, ownRow(legacy.wrapped, 0), { fetchRosters: async () => [] });
  expect(r1.pins?.epochs?.[OTHER]?.bound_since ?? null).toBe(null);
  // Never on a shared (sealed) row: its wrap isn't an account wrap at all.
  const shared = await check(w, signedRow(w));
  expect(shared.pins?.epochs?.[VID]?.bound_since ?? null).toBe(null);
  bound.free();
  legacy.free();
});

test("L6 and invitations: labels and invitation texts lead with the pinned email; the server's names only as 'listed by your server as'", () => {
  expect(ss.signedByLabel("alice@example.com", true, false)).toBe("Signed by alice@example.com (as your server lists them) (account deleted)");
  expect(ss.signedByLabel("alice@example.com", true, true)).toBe("Signed by alice@example.com (account deleted)");
  const w = world();
  const s = w.share("write");
  const inv = {
    vault_id: VID,
    role: "write" as const,
    wrapped_key: s.sealed_key,
    meta: "m",
    invited_by: { id: who("alice").user_id, email: "CEO@Example.com", name: "The CEO", public_key: "k" },
    invited_at: 1,
    key_epoch: 0,
  };
  const me = w.bobSigner.publicIdentity();
  const pins = core.pinSet(null, w.aliceSigner.publicIdentity(), "alice@example.com", true, 1);
  const signer = w.snapshot(w.aliceSigner.publicIdentity(), "Boss@Bücher.example");
  expect(ss.checkInvitation({ ...inv, share: { signature: s.signature, signer } }, me, pins, false)).toStrictEqual({
    vaultId: VID,
    state: "ok",
    from: "alice@example.com",
    listedAs: "boss@xn--bcher-kva.example",
  });
  // Not pinned yet: nobody is named as the sharer, the server's email only as its claim (normalized).
  expect(ss.checkInvitation({ ...inv, share: { signature: s.signature, signer } }, me, null, false)).toMatchObject({ state: "ok", from: "", listedAs: "boss@xn--bcher-kva.example" });
  const conflict = ss.checkInvitation({ ...inv, share: { signature: s.signature, signer: w.snapshot(who("carol"), "alice@example.com") } }, me, pins, false);
  expect(conflict).toStrictEqual({ vaultId: VID, state: "refused", from: "", listedAs: "alice@example.com" });
  expect(ss.invitationText(conflict)).toBe(
    "PassAuth couldn't verify an invitation listed by your server as from alice@example.com. Don't accept it; ask the person who shared it, or your server's admin.",
  );
  expect(ss.invitationText({ vaultId: VID, state: "unsigned", from: "", listedAs: "ceo@example.com" })).toContain("listed by your server as from ceo@example.com");
});

test("L7: a pins edit stored while a check ran (unsent, not the copy the check started from) is merged in, never dropped; no endless merging", () => {
  const stored = { ...ss.emptyMemory("u"), pinsSeq: 2, pinsSealed: "edited", pinsDirty: true };
  const ours = { ...ss.emptyMemory("u"), pinsSeq: 2, pinsSealed: "ours", pinsDirty: false };
  const merge = (h: { pinsSealed: string | null }, l: { pinsSealed: string | null }) => ({ ...ours, pinsSealed: `${h.pinsSealed}+${l.pinsSealed}`, pinsDirty: true });
  expect(ss.mergeMemory(stored, ours, merge, "start")).toMatchObject({ pinsSealed: "ours+edited", pinsDirty: true });
  // The check wrote a newer version: still merged (the edit wins its own changes back).
  expect(ss.mergeMemory({ ...stored, pinsSeq: 1 }, { ...ours, pinsSeq: 3 }, merge, "start").pinsSealed).toBe("ours+edited");
  // The stored copy is the one the check started from: already in ours.
  expect(ss.mergeMemory(stored, ours, merge, "edited")).toMatchObject({ pinsSealed: "ours", pinsDirty: false });
});

test("L5: the trust memory isn't written when reading it fails", async () => {
  installChrome();
  await storage.trustMemory.update("s", "u", () => ({ ...ss.emptyMemory("u"), pinsSeq: 7 }));
  const req = indexedDB.open("passauth", 1);
  await new Promise((resolve) => {
    req.onsuccess = resolve;
  });
  const proto = Object.getPrototypeOf(req.result) as { transaction: (n: string, m?: string) => unknown };
  const original = proto.transaction;
  proto.transaction = function (this: unknown, name: string, mode?: string) {
    if (mode === "readonly") throw new DOMException("broken", "UnknownError");
    return original.call(this, name, mode);
  };
  try {
    await expect(storage.trustMemory.update("s", "u", () => ss.emptyMemory("u"))).rejects.toThrow();
  } finally {
    proto.transaction = original;
  }
  expect(ss.readMemory(await storage.trustMemory.get("s", "u"), "u")?.pinsSeq).toBe(7);
});

// ------------------------------------------------------------------ the worker, end to end

const OWN = "00000000-0000-4000-8000-0000000000e1";
const SIGNED_FEATURES = ["key_epoch", "idempotent_create", "error_codes", "delta_sync", "vault_invitations", "signed_sharing"];

const loginItem = (name: string, url: string) => ({
  name,
  notes: "",
  favorite: false,
  folder: null,
  tags: [],
  login: { username: "bob", password: `pw-${name}`, urls: [{ url, match: "domain" }], totp: null, passkeys: [] },
  card: null,
  identity: null,
  ssh_key: null,
  fields: [],
  password_history: [],
  created_at: 0,
  updated_at: 0,
});

let fake: FakeChrome;
let server: FakeServer;

interface Setup {
  features?: string[];
  /** Bob's `user.identity` on the server (default: his record from the vectors). */
  identity?: core.IdentityRecord | null;
  /** The shared vault's row fields (wrapped key, share, roster) besides the defaults. */
  shared?: (w: World) => Record<string, unknown>;
  /** The rosters the server serves for the shared vault (default: v1). */
  rosters?: (w: World) => string[];
  /**
   * Bob's key pins on the server (version 1) before this browser: default = the shared vault accepted at epoch 0 with
   * roster v1, and his own identity remembered; null: none.
   */
  pins?: (w: World) => core.KeyPins | null;
  /** Runs just before the first unlock (handlers set by then, e.g. to make an upload fail). */
  beforeUnlock?: (w: World) => void;
  /** Only set the server and the account up: nothing is unlocked or synced. */
  noUnlock?: boolean;
}

const putItem = (vaultId: string, key: core.VaultKey, id: string, item: unknown) => {
  const enc = key.encryptItem(item, id, vaultId) as { key: string; data: string };
  server.items.push({ id, vault_id: vaultId, item_key: enc.key, data: enc.data, revision: ++server.revision, deleted_at: null, seq: server.bump(vaultId) });
};

/** Bob signed in on the server with his own vault and Alice's shared vault, each with one login; the vault opened. */
async function bobSignedIn(setup: Setup = {}) {
  await vault.lockAll().catch(() => {});
  fake = installChrome();
  server = fakeServer();
  server.features = setup.features ?? SIGNED_FEATURES;
  const w = world();
  const own = w.bob.newVaultKey(OWN);
  const ownKey = own.takeKey();
  const bobId = V.accounts[1]!.id;
  const s = w.share("write");
  server.user = { id: bobId, email: "bob@example.com", name: "Bob", email_verified: true, identity: setup.identity === undefined ? V.accounts[1]!.record : setup.identity, key_pins_seq: 0 } as never;
  server.bundle = { account_id: bobId, secret_key_enabled: false };
  server.vaults = [
    { id: OWN, wrapped_key: own.wrapped, key_kind: "account", role: "owner", meta: ownKey.encryptMeta(OWN, { name: "Bob" }), key_epoch: 0 },
    {
      id: VID,
      wrapped_key: s.sealed_key,
      key_kind: "sealed",
      role: "write",
      meta: w.key.encryptMeta(VID, { name: "Team" }),
      key_epoch: 0,
      share: { signature: s.signature, signer: w.signerSnap, signer_deleted: false },
      member_roster: w.v1,
      member_roster_seq: 1,
      ...(setup.shared?.(w) ?? {}),
    } as never,
  ];
  putItem(OWN, ownKey, "00000000-0000-4000-8000-000000000101", loginItem("Own", "https://own.example"));
  putItem(VID, w.key, "00000000-0000-4000-8000-000000000102", loginItem("Team login", "https://team.example"));
  // The account's key pins and signing identity on the server.
  const initial = setup.pins ? setup.pins(w) : core.pinsSetOwnIdentity(w.accepted(), ident("bob").hash);
  const stored = { pins: initial ? w.bob.sealKeyPins(initial, 1) : (null as string | null), seq: initial ? 1 : 0 };
  if (initial) (server.user as unknown as { key_pins_seq: number }).key_pins_seq = 1;
  server.handlers["GET /account/key-pins"] = () => ({ body: { key_pins: stored.pins, seq: stored.seq } });
  server.handlers["PUT /account/key-pins"] = (req) => {
    if (req.body.seq !== stored.seq + 1) return { status: 409, body: { error: "key_pins_changed", message: "changed" } };
    stored.pins = req.body.key_pins;
    stored.seq = req.body.seq;
    (server.user as unknown as { key_pins_seq: number }).key_pins_seq = stored.seq;
    server.revision++;
    return { body: { seq: stored.seq } };
  };
  server.handlers["PUT /account/identity"] = (req) => {
    (server.user as unknown as { identity: unknown }).identity = req.body;
    server.revision++;
    return { body: { ok: true, created: true } };
  };
  const rosters = setup.rosters ? setup.rosters(w) : [w.v1];
  server.handlers[`GET /vaults/${VID}/rosters`] = (req) => {
    const after = Number(req.query.after ?? 0);
    return { body: { rosters: rosters.slice(after), latest: rosters.length, more: false } };
  };
  vi.stubGlobal("fetch", server.fetch);
  forgetServerFeatures();
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  setup.beforeUnlock?.(w);
  if (!setup.noUnlock) expect(await vault.ensureUnlocked()).toBe(true);
  return { w, ownKey, stored, bob: accountOf("bob") };
}

/**
 * The vectors carry session bytes but no account bundles, so the worker tests can't hand the core a bundle it
 * authenticates: `Account.matchesBundle` answers as the core does for the account id (a bundle of this account's own id
 * matches), and false for a bundle a test marks as the server's swap (`swapped: true`).
 */
const stubMatchesBundle = () =>
  vi.spyOn(core.Account.prototype, "matchesBundle").mockImplementation(function (this: core.Account, b: unknown) {
    const bundle = b as { account_id?: unknown; swapped?: unknown } | null;
    return !!bundle && bundle.account_id === this.legacyIdentity().user_id && bundle.swapped !== true;
  });

const sessionFor = (name: string) => {
  const a = V.accounts.find((x) => x.name === name)!;
  const bytes = fromB64u(a.sessionBytes);
  return { accountId: a.id, keys: btoa(String.fromCharCode(...bytes)), bundle: { account_id: a.id, secret_key_enabled: false } };
};

const names = () =>
  vault
    .allEntries()
    .map((e) => e.item.name)
    .sort();
const userField = (k: string, v: unknown) => {
  (server.user as unknown as Record<string, unknown>)[k] = v;
  server.revision++;
};

/** Carol (an identity the server controls) shares a vault of her own with Bob: the row, its roster and its key. */
function carolsVault(w: World, vaultId: string, email: string) {
  const carolAcct = accountOf("carol");
  const carol = carolAcct.openSigningIdentity(V.accounts[2]!.record);
  const key = carolAcct.newVaultKey(vaultId).takeKey();
  const s = carol.sealAndSignShare(key, vaultId, w.bobSigner.publicIdentity(), "write", 0);
  const members = [
    { ...carol.publicIdentity(), role: "owner" },
    { ...w.bobSigner.publicIdentity(), role: "write" },
  ];
  const roster = carol.signRoster(key, vaultId, null, 0, members, core.rosterReview(vaultId, null, carol.publicIdentity(), members, null).digest);
  const row = {
    id: vaultId,
    wrapped_key: s.sealed_key,
    key_kind: "sealed",
    role: "write",
    meta: key.encryptMeta(vaultId, { name: "Planted" }),
    key_epoch: 0,
    share: { signature: s.signature, signer: w.snapshot(carol.publicIdentity(), email, "Colleague"), signer_deleted: false },
    member_roster: roster,
    member_roster_seq: 1,
  };
  return { row, roster, key, fingerprint: carol.fingerprint() };
}

beforeEach(() => {
  vi.unstubAllGlobals();
  // Restored after every test (vitest `restoreMocks`).
  stubMatchesBundle();
});

test("worker: a verified shared vault's logins are used; the key pins (new signer, own vault's epoch) are written once", async () => {
  const { stored, bob, w } = await bobSignedIn();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()).toBe(null);
  const team = vault.allEntries().find((e) => e.item.name === "Team login")!;
  expect(vault.summarize(team).vaultLabel).toBeUndefined();
  expect(vault.vaultTrust(team.vaultId).signer).toMatchObject({ email: "alice@example.com", pinned: false, fingerprint: ident("alice").fingerprint, verified: false });
  expect(vault.sharingIdentity()).toStrictEqual({ fingerprint: ident("bob").fingerprint, paused: false });
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/key-pins").map((r) => r.body.seq)).toStrictEqual([2]);
  const pins = bob.openKeyPins(stored.pins!, 2);
  expect(pins.pins.map((p) => p.email)).toStrictEqual(["alice@example.com"]);
  expect(Object.keys(pins.epochs ?? {}).sort()).toStrictEqual([OWN, VID].sort());
  expect(pins.epochs?.[VID]?.signed_since).toBe(1);
  expect(pins.own_identity).toBe(ident("bob").hash);
  // Grandfathering happens only when this unlock made the identity: written, empty.
  expect(pins.grandfathered).toStrictEqual({});
  // A later sync doesn't write them again.
  await vault.sync();
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/key-pins")).toHaveLength(1);
  // The offline copy keeps the verdicts; the trust memory is under the server's address and the core's account id.
  const copy = await storage.syncCache.get("a1");
  expect(Object.fromEntries(Object.entries(copy?.trust ?? {}).map(([id, v]) => [id, v.trust.state]))).toStrictEqual({ [OWN]: "ok", [VID]: "ok" });
  const memory = ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id);
  expect(memory?.rosters[VID]).toBe(w.v1);
  expect(memory?.pinsSeq).toBe(2);
  expect((await fake.local.get("accounts")).accounts.a1.userId).toBe(V.accounts[1]!.id);
});

test("worker: an account with a signing identity but no key pins anywhere (lost memory): nothing grandfathered, the shared vault waits, a warning", async () => {
  await bobSignedIn({ pins: () => null });
  expect(names()).toStrictEqual(["Own"]);
  const notice = vault.sharingNotice();
  expect(notice?.warnings).toContain(ss.MEMORY_MISSING_TEXT);
  expect(notice?.waiting.map((x) => [x.vaultId, x.name, x.acceptable])).toStrictEqual([[VID, "Team", true]]);
  await vault.acceptSharedVault(VID, notice!.waiting[0]!.token);
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("worker: trust memory missing: an unsigned shared vault waits, may be accepted once (the key shown), and the warning goes", async () => {
  await bobSignedIn({ pins: () => null, shared: (w) => ({ wrapped_key: w.key.shareTo(VID, who("bob").public_key), share: null, member_roster: null, member_roster_seq: 0 }) });
  expect(names()).toStrictEqual(["Own"]);
  const notice = vault.sharingNotice();
  expect(notice?.warnings).toContain(ss.MEMORY_MISSING_TEXT);
  const w = notice?.waiting[0];
  expect(w).toMatchObject({ vaultId: VID, acceptable: true, note: ss.UNSIGNED_LABEL });
  await vault.acceptSharedVault(VID, w!.token);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()).toBe(null);
  const team = vault.allEntries().find((e) => e.item.name === "Team login")!;
  expect(vault.summarize(team).vaultLabel).toBe("Not yet signed");
});

test("worker H3: a vault planted after the first signed sync isn't used; it waits for consent, and accepting it (from the signer shown) makes it usable", async () => {
  const { w } = await bobSignedIn();
  const planted = carolsVault(w, OTHER, "carol@example.com");
  server.vaults.push(planted.row as never);
  putItem(OTHER, planted.key, "00000000-0000-4000-8000-000000000103", loginItem("Planted login", "https://team.example"));
  server.handlers[`GET /vaults/${OTHER}/rosters`] = () => ({ body: { rosters: [planted.roster], latest: 1, more: false } });
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect((await vault.unlockedIndex())?.logins).toHaveLength(2);
  const notice = vault.sharingNotice();
  expect(notice?.waiting).toStrictEqual([
    {
      vaultId: OTHER,
      name: "Planted",
      text: ss.waitingText("Planted"),
      signer: { email: "carol@example.com", pinned: false, listedAs: "Colleague", deleted: false, fingerprint: planted.fingerprint, verified: false },
      acceptable: true,
      token: expect.any(String),
      replaced: false,
      own: false,
      // Round 5 M2: a plain signed consent may be declined (in the web vault).
      firstSigned: false,
      declinable: true,
    },
  ]);
  expect(notice?.vaultsUrl).toBe("https://vault.test/settings/vaults");
  // Only with the token of what was shown.
  await expect(vault.acceptSharedVault(OTHER, planted.fingerprint)).rejects.toThrow();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  await vault.acceptSharedVault(OTHER, notice!.waiting[0]!.token);
  expect(names()).toStrictEqual(["Own", "Planted login", "Team login"]);
  expect(vault.sharingNotice()).toBe(null);
});

test("worker H3: a planted vault 'from' a pinned colleague's email under another account stops with email_conflict", async () => {
  const { w } = await bobSignedIn();
  const planted = carolsVault(w, OTHER, "Alice@example.com");
  server.vaults.push(planted.row as never);
  server.handlers[`GET /vaults/${OTHER}/rosters`] = () => ({ body: { rosters: [planted.roster], latest: 1, more: false } });
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()?.refused).toMatchObject([{ vaultId: OTHER, changed: { kind: "email_conflict", email: "alice@example.com" } }]);
  // Nothing to trust for an email conflict.
  await expect(vault.trustNewKey(who("carol").user_id, planted.fingerprint)).rejects.toThrow();
});

test("worker H1: a sync for another account (tampered user.id) is refused: nothing shown, kept or remembered under it", async () => {
  await bobSignedIn();
  const before = await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id);
  userField("id", V.accounts[0]!.id);
  await expect(vault.sync()).rejects.toThrow(ss.WRONG_ACCOUNT_TEXT);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[0]!.id)).toBeUndefined();
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id)).toStrictEqual(before);
  expect((await storage.syncCache.get("a1"))?.user.id).toBe(V.accounts[1]!.id);
  // An offline copy for another account is never opened (a sync replaces it).
  await vault.lockAll();
  const copy = await storage.syncCache.get("a1");
  await storage.syncCache.set("a1", { ...copy!, user: { ...copy!.user, id: V.accounts[0]!.id } });
  vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  await vault.ensureUnlocked().catch(() => false);
  expect(names()).toStrictEqual([]);
});

test("worker L4: once the account remembers its identity, a server listing none (or another) pauses sharing; own vaults stay", async () => {
  await bobSignedIn();
  userField("identity", null);
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.PAUSED_TEXT);
  // Nothing new is made over the remembered one.
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/identity")).toHaveLength(0);
  userField("identity", V.accounts[2]!.record);
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingIdentity()).toStrictEqual({ fingerprint: null, paused: true });
  userField("identity", V.accounts[1]!.record);
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("worker: a forged share (the server raised the role) is never used: not listed, not matched, not offered for saving; the popup says why", async () => {
  await bobSignedIn({ shared: () => ({ role: "admin" }) });
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.refused).toStrictEqual([{ vaultId: VID, reason: ss.refusedText("not_listed") }]);
  expect(vault.editorInfo().vaults.map((v) => v.id)).toStrictEqual([OWN]);
  const index = await vault.unlockedIndex();
  expect(index?.logins.map((l) => l.urls[0]?.url)).toStrictEqual(["https://own.example"]);
});

test("worker: verdicts survive an offline reopen: a refused vault stays out, a verified one stays in", async () => {
  await bobSignedIn({ shared: () => ({ role: "admin" }) });
  expect(names()).toStrictEqual(["Own"]);
  await vault.lockAll();
  vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.refused).toHaveLength(1);

  await bobSignedIn();
  await vault.lockAll();
  vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("worker: a server that drops signed sharing is refused: its unsigned share of a vault seen signed is never fetched", async () => {
  await bobSignedIn();
  server.outdated = "unsigned";
  forgetServerFeatures();
  const row = server.vaults[1] as unknown as Record<string, unknown>;
  row.share = null;
  row.member_roster = null;
  row.member_roster_seq = 0;
  server.revision++;
  const before = server.requests.length;
  await expect(vault.sync()).rejects.toThrow(SERVER_UPDATE_TEXT);
  expect(server.requests.slice(before).map((r) => r.path)).toStrictEqual(["/config"]);
  // What was checked before stays as it was.
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("worker: a server whose features can't be read gets no benefit of the doubt: a new browser doesn't use it at all; one that knew it as signing checks its rows (and refuses them), never unchecked", async () => {
  // Rows made to look like an old server's (no key epochs, nothing signed), with `/api/config` failing.
  const setup = (): Setup => ({
    identity: null,
    pins: () => null,
    shared: (w) => ({ wrapped_key: w.key.shareTo(VID, who("bob").public_key), share: undefined, member_roster: undefined, member_roster_seq: undefined, key_epoch: undefined }),
    noUnlock: true,
    beforeUnlock: () => {
      server.handlers["GET /config"] = () => ({ status: 500, body: {} });
      userField("key_pins_seq", undefined);
    },
  });
  // A new browser (no feature list ever read from this server): "can't reach", and no sync answer is asked for or used.
  await bobSignedIn(setup());
  await expect(vault.ensureUnlocked()).rejects.toThrow(UNREACHABLE_TEXT);
  await expect(vault.sync()).rejects.toThrow(UNREACHABLE_TEXT);
  await expect(vault.login("bob@example.com", "pw")).rejects.toThrow(UNREACHABLE_TEXT);
  expect([...new Set(server.requests.map((r) => r.path))]).toStrictEqual(["/config"]);
  expect(names()).toStrictEqual([]);
  expect(await storage.syncCache.get("a1")).toBeUndefined();
  // A browser that read `signed_sharing` from this server before: it goes on (offline use), with the checks on.
  await bobSignedIn(setup());
  await storage.knownFeatures.set("https://vault.test", SIGNED_FEATURES);
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(names()).toStrictEqual(["Own"]);
  expect((await storage.syncCache.get("a1"))?.checks).toBeUndefined();
});

test("worker: servers without signed sharing are refused (API 2 without the feature, and servers from before API 2): no sign-in, no sync, nothing written", async () => {
  for (const kind of ["unsigned", "old"] as const) {
    await bobSignedIn({ noUnlock: true, beforeUnlock: () => (server.outdated = kind) });
    // Restoring the keys works (nothing is asked for that); the first sync is refused before `/sync` is asked.
    await expect(vault.ensureUnlocked()).rejects.toThrow(SERVER_UPDATE_TEXT);
    await expect(vault.sync()).rejects.toThrow(SERVER_UPDATE_TEXT);
    await expect(vault.login("bob@example.com", "pw")).rejects.toThrow(SERVER_UPDATE_TEXT);
    expect(
      server.requests.map((r) => r.path),
      kind,
    ).toStrictEqual(["/config"]);
    expect(names(), kind).toStrictEqual([]);
    expect(await vault.serverNeedsUpdate(), kind).toBe(true);
    // Setting that address as the server is refused too; an address where nothing answers isn't "outdated".
    await expect(vault.setServer("https://vault.test"), kind).rejects.toThrow(SERVER_UPDATE_TEXT);
  }
});

test("worker: a refused server leaves the offline copy usable (read only), as when the server can't be reached; an upgraded server syncs again", async () => {
  await bobSignedIn();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  // The server is downgraded (or starts leaving the feature out); the browser unlocks again later.
  await vault.lockAll();
  server.outdated = "unsigned";
  forgetServerFeatures();
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  const before = server.requests.length;
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  await expect(vault.sync()).rejects.toThrow(SERVER_UPDATE_TEXT);
  const own = vault.allEntries().find((e) => e.item.name === "Own")!;
  await expect(vault.updateItem(own, { ...own.item, notes: "changed" })).rejects.toThrow(SERVER_UPDATE_TEXT);
  await expect(vault.createItem(own.item)).rejects.toThrow(SERVER_UPDATE_TEXT);
  await expect(vault.trashItem(own)).rejects.toThrow(SERVER_UPDATE_TEXT);
  expect(await vault.checkForChanges()).toBe("unsupported");
  expect([...new Set(server.requests.slice(before).map((r) => r.path))]).toStrictEqual(["/config"]);
  expect(await vault.serverNeedsUpdate()).toBe(true);
  // Unreachable is not a refusal.
  vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
  forgetServerFeatures();
  expect(await vault.serverNeedsUpdate()).toBe(false);
  // Updated: everything works again.
  vi.stubGlobal("fetch", server.fetch);
  server.outdated = null;
  forgetServerFeatures();
  await vault.sync();
  expect(await vault.serverNeedsUpdate()).toBe(false);
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

const unsignedShare = (w: World) => ({ wrapped_key: w.key.shareTo(VID, who("bob").public_key), share: null, member_roster: null, member_roster_seq: 0 });
const identityPuts = () => server.requests.filter((r) => r.method === "PUT" && r.path === "/account/identity");
/**
 * A new unlock in a new browser session: the keys come from disk (the timeout "never") and the session storage is
 * empty, so the offline copy is one from an earlier session (a reload from the session is a worker restart instead).
 */
async function unlockFromDisk() {
  const l = (await fake.local.get(["accounts", "settings"])) as { accounts: Record<string, object>; settings?: object };
  await fake.local.set({ accounts: { ...l.accounts, a1: { ...l.accounts.a1, persistedKeys: sessionFor("bob") } }, settings: { ...(l.settings ?? {}), vaultTimeout: "never" } });
  expect(await vault.ensureUnlocked()).toBe(true);
}
/** Unlock again in a new session (the offline copy kept), with what the server answers now. */
async function unlockAgain() {
  await vault.lockAll();
  await fake.session.clear();
  await unlockFromDisk();
  server.revision++;
  await vault.sync();
}
/**
 * Bob used an earlier version of the extension with the server before it signed: this browser holds an offline copy
 * with the shared vault, written without checks. (This version never syncs with such a server, so the copy is put
 * there as that version stored it: a full `/sync` answer.) Versions from before signed sharing left no mark
 * (`oldExtension`); later ones marked a copy written with the checks off (round 5 H). Then the server signs.
 */
async function beforeSigning(oldExtension = true) {
  const ctx = await bobSignedIn({ identity: null, pins: () => null, shared: unsignedShare, noUnlock: true });
  const answer = server.syncAnswer({ trash: "summary" }) as never as NonNullable<Awaited<ReturnType<typeof storage.syncCache.get>>>;
  await storage.syncCache.set("a1", oldExtension ? answer : { ...answer, checks: "off" });
  return ctx;
}
const serverPins = (stored: { pins: string | null; seq: number }) => accountOf("bob").openKeyPins(stored.pins!, stored.seq);

test("worker: a share from before, in this browser's offline copy from an earlier session, is grandfathered at the first signed sync: 'Not yet signed' and still used", async () => {
  const { stored } = await beforeSigning();
  await unlockAgain();
  expect(identityPuts()).toHaveLength(1);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const team = vault.allEntries().find((e) => e.item.name === "Team login")!;
  expect(vault.summarize(team).vaultLabel).toBe("Not yet signed");
  expect(vault.editorInfo().defaultVault).toBe(OWN);
  expect(Object.keys(serverPins(stored).grandfathered ?? {}).sort()).toStrictEqual([OWN, VID].sort());
  expect(vault.sharingNotice()).toBe(null);
});

test("M1: a browser with no earlier offline copy grandfathers nothing: an unsigned shared vault waits (even if the server says this unlock made the identity), accepted only by the token shown", async () => {
  const { stored } = await bobSignedIn({ identity: null, pins: () => null, shared: unsignedShare });
  expect(identityPuts()).toHaveLength(1);
  expect(names()).toStrictEqual(["Own"]);
  expect(serverPins(stored).grandfathered).toStrictEqual({});
  const notice = vault.sharingNotice();
  expect(notice?.warnings).toStrictEqual([ss.NEW_DEVICE_TEXT]);
  expect(notice?.waiting).toMatchObject([{ vaultId: VID, acceptable: true, note: ss.UNSIGNED_LABEL }]);
  await expect(vault.acceptSharedVault(VID, "something else")).rejects.toThrow();
  await vault.acceptSharedVault(VID, notice!.waiting[0]!.token);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()).toBe(null);
});

test("M1: after a worker restart, this session's own offline copy doesn't count as an earlier one", async () => {
  // The first signed sync's upload fails (M2: nothing grandfathered), the copy with the vault is kept meanwhile.
  const { stored } = await bobSignedIn({
    identity: null,
    pins: () => null,
    shared: unsignedShare,
    beforeUnlock: () => {
      server.handlers["PUT /account/identity"] = () => ({ status: 500, body: { error: "internal", message: "boom" } });
    },
  });
  expect(names()).toStrictEqual(["Own"]);
  expect((await storage.syncCache.get("a1"))?.vaults.map((v) => v.id)).toContain(VID);
  // The worker restarts (session storage stays), and the upload works now.
  const earlierIds = fake.session.data.get("earlier:a1");
  expect(earlierIds ?? []).toStrictEqual([]);
  await vault.lockAll();
  await fake.session.set({ "unlocked:a1": sessionFor("bob"), ...(earlierIds ? { "earlier:a1": earlierIds } : {}) });
  server.handlers["PUT /account/identity"] = (req) => {
    (server.user as unknown as { identity: unknown }).identity = req.body;
    server.revision++;
    return { body: { ok: true, created: true } };
  };
  expect(await vault.ensureUnlocked()).toBe(true);
  server.revision++;
  await vault.sync();
  expect(identityPuts()).toHaveLength(2);
  expect(serverPins(stored).grandfathered).toStrictEqual({});
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.waiting).toMatchObject([{ vaultId: VID, acceptable: true }]);
});

test("M2: grandfathering waits while the identity state is unknown (upload failed, identity_exists) instead of writing an empty list for the account", async () => {
  const { stored } = await beforeSigning();
  server.handlers["PUT /account/identity"] = () => ({ status: 503, body: { error: "unavailable", message: "later" } });
  await unlockAgain();
  expect(names()).toStrictEqual(["Own"]);
  expect(serverPins(stored).grandfathered ?? null).toBe(null);
  server.handlers["PUT /account/identity"] = () => ({ status: 409, body: { error: "identity_exists", message: "exists" } });
  server.revision++;
  await vault.sync();
  expect(serverPins(stored).grandfathered ?? null).toBe(null);
  // Answered at last: the vault from before is grandfathered after all.
  server.handlers["PUT /account/identity"] = (req) => {
    (server.user as unknown as { identity: unknown }).identity = req.body;
    server.revision++;
    return { body: { ok: true, created: true } };
  };
  server.revision++;
  await vault.sync();
  expect(Object.keys(serverPins(stored).grandfathered ?? {}).sort()).toStrictEqual([OWN, VID].sort());
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("B: an upload whose answer was lost still counts as made here once the server lists that identity (no empty grandfathered list)", async () => {
  const { stored } = await beforeSigning();
  server.handlers["PUT /account/identity"] = (req) => {
    (server.user as unknown as { identity: unknown }).identity = req.body;
    server.revision++;
    return { status: 502, body: { error: "bad_gateway", message: "lost" } };
  };
  await unlockAgain();
  expect(serverPins(stored).grandfathered ?? null).toBe(null);
  server.revision++;
  await vault.sync();
  expect(identityPuts()).toHaveLength(1);
  expect(Object.keys(serverPins(stored).grandfathered ?? {}).sort()).toStrictEqual([OWN, VID].sort());
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const memory = ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id);
  expect(memory?.pendingIdentities).toBeUndefined();
  expect(memory?.candidates).toBeUndefined();
});

test("A: while the server's features are unknown the checks run, but nothing turns them on for good; known again as a server that doesn't sign: refused", async () => {
  // (A browser that read this server's feature list before: without one, a server whose config fails isn't used at all.)
  await bobSignedIn({
    identity: null,
    pins: () => null,
    shared: unsignedShare,
    noUnlock: true,
    beforeUnlock: () => {
      server.handlers["GET /config"] = () => ({ status: 500, body: {} });
      userField("key_pins_seq", undefined);
    },
  });
  await storage.knownFeatures.set("https://vault.test", SIGNED_FEATURES);
  expect(await vault.ensureUnlocked()).toBe(true);
  // Checked (unknown is never "off"): the unsigned share waits…
  expect(names()).toStrictEqual(["Own"]);
  // …but nothing was kept that would keep the checks on, and no identity was made for a server that may not sign.
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id)).toBeUndefined();
  expect(server.requests.filter((r) => r.path.startsWith("/account/"))).toStrictEqual([]);
  delete server.handlers["GET /config"];
  server.outdated = "unsigned";
  forgetServerFeatures();
  server.revision++;
  await expect(vault.sync()).rejects.toThrow(SERVER_UPDATE_TEXT);
  expect(names()).toStrictEqual(["Own"]);
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id)).toBeUndefined();
});

const legacyRoster = (w: World) => w.roster(null, 0, "write", w.key, VID, who("bob", true));
/** Bob's pins after he accepted the vault at epoch 0 with the roster naming his legacy identity. */
const legacyAccepted = (w: World) => core.pinsRecordRotation(null, VID, "sealed", w.key.epochPin(VID, 0), 1, core.rosterHash(legacyRoster(w)));

test("worker: without a signing identity on the server, one is made (with its X25519 signature) and uploaded once, and used", async () => {
  await bobSignedIn({
    identity: null,
    // Accepted with the roster Alice signed then (round 5: a pinned roster version always carries its hash).
    pins: (w) => legacyAccepted(w),
    // Alice shared the vault while Bob had no signing key yet: her share and roster name his legacy identity.
    shared: (w) => {
      const s = w.share("write", 0, who("bob", true));
      return { wrapped_key: s.sealed_key, share: { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, member_roster: legacyRoster(w) };
    },
    rosters: (w) => [legacyRoster(w)],
  });
  const puts = server.requests.filter((r) => r.method === "PUT" && r.path === "/account/identity");
  expect(puts).toHaveLength(1);
  expect(Object.keys(puts[0]!.body).sort()).toStrictEqual(["identity_signature", "signing_key", "wrapped_signing_key", "x25519_signature"]);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingIdentity().fingerprint).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/);
  await vault.sync();
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/identity")).toHaveLength(1);
});

test("worker: a signing identity that isn't this account's pauses sharing: shared vaults aren't used, the popup says so", async () => {
  await bobSignedIn({ identity: V.accounts[2]!.record });
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.PAUSED_TEXT);
  expect(vault.sharingIdentity()).toStrictEqual({ fingerprint: null, paused: true });
});

test("worker: a verified roster is remembered; a later rollback of it is refused", async () => {
  await bobSignedIn({ rosters: () => [] });
  // The server didn't serve it: refused until it does.
  expect(names()).toStrictEqual(["Own"]);
  const v1 = (server.vaults[1] as unknown as { member_roster: string }).member_roster;
  server.handlers[`GET /vaults/${VID}/rosters`] = () => ({ body: { rosters: [v1], latest: 1, more: false } });
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const row = server.vaults[1] as unknown as Record<string, unknown>;
  row.member_roster = null;
  row.member_roster_seq = 0;
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
});

test("worker: unsigned invitations on a signed server are named in the popup's notice", async () => {
  await bobSignedIn();
  server.invitations = [
    {
      vault_id: "00000000-0000-4000-8000-0000000000f9",
      role: "write",
      wrapped_key: "x",
      meta: "m",
      invited_by: { id: "u", email: "eve@example.com", name: "Eve", public_key: "k" },
      invited_at: 1,
      key_epoch: 0,
      share: null,
    },
  ];
  server.revision++;
  await vault.sync();
  expect(vault.sharingNotice()?.invitations).toStrictEqual([
    {
      vaultId: "00000000-0000-4000-8000-0000000000f9",
      text: "An invitation listed by your server as from eve@example.com isn't signed. Ask the person who shared it to update PassAuth and share again.",
    },
  ]);
});

test("worker: a pinned person's keys changed: their vault stops until the user trusts exactly the new key shown", async () => {
  await bobSignedIn();
  const bob = accountOf("bob");
  const w = world();
  // Bob's pins on the server already hold Alice with other (legacy) keys, his own identity, and the vault accepted.
  let pins = core.pinSet(null, { ...who("alice", true), public_key: who("carol").public_key }, "alice@example.com", true, 1000);
  pins = core.pinsSetOwnIdentity(w.accepted(pins), ident("bob").hash);
  await vault.lockAll();
  fake = installChrome();
  const stored = { pins: bob.sealKeyPins(pins, 1), seq: 1 };
  server.handlers["GET /account/key-pins"] = () => ({ body: { key_pins: stored.pins, seq: stored.seq } });
  server.handlers["PUT /account/key-pins"] = (req) => {
    if (req.body.seq !== stored.seq + 1) return { status: 409, body: { error: "key_pins_changed", message: "changed" } };
    stored.pins = req.body.key_pins;
    stored.seq = req.body.seq;
    (server.user as unknown as { key_pins_seq: number }).key_pins_seq = stored.seq;
    return { body: { seq: stored.seq } };
  };
  userField("key_pins_seq", 1);
  await fake.local.set({ accounts: { a1: accountRecord() }, active: "a1" });
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(names()).toStrictEqual(["Own"]);
  const refused = vault.sharingNotice()?.refused[0];
  expect(refused?.changed).toMatchObject({ kind: "changed", userId: who("alice").user_id, email: "alice@example.com", fingerprint: ident("alice").fingerprint });
  // Another fingerprint than the one shown is never pinned.
  await expect(vault.trustNewKey(who("alice").user_id, ident("carol").fingerprint)).rejects.toThrow();
  await vault.trustNewKey(who("alice").user_id, ident("alice").fingerprint);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const after = bob.openKeyPins(stored.pins, stored.seq);
  expect(core.pinCheck(after, who("alice"), null)).toBe("match");
  expect(after.pins.find((p) => p.user_id === who("alice").user_id)).toMatchObject({ verified: true, email: "alice@example.com" });
});

test("L3: an identity made here is in the offline copy: an offline reopen isn't paused", async () => {
  await bobSignedIn({
    identity: null,
    pins: (w) => legacyAccepted(w),
    shared: (w) => {
      const s = w.share("write", 0, who("bob", true));
      return { wrapped_key: s.sealed_key, share: { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, member_roster: legacyRoster(w) };
    },
    rosters: (w) => [legacyRoster(w)],
  });
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(typeof (await storage.syncCache.get("a1"))?.user.identity).toBe("object");
  await vault.lockAll();
  vi.stubGlobal("fetch", async () => Promise.reject(new TypeError("Failed to fetch")));
  await fake.session.set({ "unlocked:a1": sessionFor("bob") });
  expect(await vault.ensureUnlocked()).toBe(true);
  expect(vault.sharingIdentity().paused).toBe(false);
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("offline key pins on a new browser (the server lists them, the fetch fails): own vaults used, shared ones checked later, nothing grandfathered or written", async () => {
  await bobSignedIn({
    beforeUnlock: () => {
      server.handlers["GET /account/key-pins"] = () => ({ status: 500, body: { error: "internal", message: "boom" } });
    },
  });
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.refused).toStrictEqual([{ vaultId: VID, reason: ss.CHECK_LATER_TEXT }]);
  expect(vault.sharingNotice()?.warnings ?? []).not.toContain(ss.MEMORY_MISSING_TEXT);
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id)).toBeUndefined();
  // Listed but not given (L4) is the same on a new browser.
  server.handlers["GET /account/key-pins"] = () => ({ body: { key_pins: null, seq: 1 } });
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  expect(server.requests.filter((r) => r.method === "PUT")).toStrictEqual([]);
});

test("L4: a newer key pins version listed without its pins isn't checked against this browser's older ones", async () => {
  const { w } = await bobSignedIn();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const planted = carolsVault(w, OTHER, "carol@example.com");
  server.vaults.push(planted.row as never);
  server.handlers[`GET /vaults/${OTHER}/rosters`] = () => ({ body: { rosters: [planted.roster], latest: 1, more: false } });
  userField("key_pins_seq", 9);
  server.handlers["GET /account/key-pins"] = () => ({ body: { key_pins: null, seq: 9 } });
  const puts = server.requests.filter((r) => r.method === "PUT").length;
  await vault.sync();
  // Nothing was decided on the older pins: the new row has no verdict (closed), nothing written.
  expect(vault.sharingNotice()?.waiting ?? []).toStrictEqual([]);
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(server.requests.filter((r) => r.method === "PUT").length).toBe(puts);
});

test("rule 3: an accepted shared vault missing from one verified sync isn't given up; missing from two in a row it is remembered as left", async () => {
  const { stored } = await bobSignedIn();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  const row = server.vaults.splice(1, 1)[0]!;
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  // One sync that omitted it: nothing remembered as left (a server omitting a vault once can't make the account give it up).
  expect(serverPins(stored).left?.[VID]).toBeUndefined();
  server.vaults.push(row);
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  // Missing from two verified syncs in a row: confirmed, tombstoned with its roster version.
  server.vaults.splice(1, 1);
  server.revision++;
  await vault.sync();
  expect(serverPins(stored).left?.[VID]).toBeUndefined();
  server.revision++;
  await vault.sync();
  expect(serverPins(stored).left?.[VID]).toMatchObject({ roster_version: 1 });
  // The server can't bring it back.
  server.vaults.push(row);
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.refused).toMatchObject([{ vaultId: VID }]);
});

test("rule 3: a removal its rosters confirm (404: not a member) is remembered as left at once; a 403 confirms nothing (round 5 Info)", async () => {
  for (const [status, left] of [
    [403, false],
    [404, true],
  ] as const) {
    const { stored } = await bobSignedIn();
    server.vaults.splice(1, 1);
    server.handlers[`GET /vaults/${VID}/rosters`] = () => ({ status, body: { error: status === 404 ? "not_found" : "two_step_required", message: "no" } });
    server.revision++;
    await vault.sync();
    expect(serverPins(stored).left?.[VID], String(status)).toEqual(left ? expect.objectContaining({ roster_version: 1 }) : undefined);
  }
});

test("L6: a vault signed by an account deleted since, not pinned here: the label marks the email as the server's and the fingerprint stays shown", async () => {
  await bobSignedIn({
    shared: (w) => {
      const s = w.share("write");
      return { wrapped_key: s.sealed_key, share: { signature: s.signature, signer: w.signerSnap, signer_deleted: true } };
    },
  });
  const team = vault.allEntries().find((e) => e.item.name === "Team login")!;
  const t = vault.vaultTrust(team.vaultId);
  expect(t.vaultLabel).toBe("Signed by alice@example.com (as your server lists them) (account deleted)");
  expect(t.signer).toMatchObject({ pinned: false, deleted: true, fingerprint: ident("alice").fingerprint });
});

// ------------------------------------------------------------------ round 4 (core round 4 + final web/extension review)

/** Alice's second key, sealed and signed by `signer` to Bob at `epoch`, with a roster version 1 of its own at that epoch. */
function secondKeyRow(w: World, epoch: number) {
  const second = aliceKey("secondKeyV2");
  const s = w.aliceSigner.sealAndSignShare(second, VID, w.bobSigner.publicIdentity(), "write", epoch);
  const roster = w.roster(null, epoch, "write", second);
  const row = sealedRow(s.sealed_key, "write", epoch, { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, roster);
  return { second, row, roster };
}

test("round 4 (puppet signer): a signed new key on a vault never seen signed waits for consent, naming the signer; accepting goes through pinsAccept", async () => {
  const w = world();
  // Bob had the vault from before (grandfathered, unsigned) at epoch 0; a key signed for the first time arrives at epoch 1.
  const pins = core.pinsRecordRotation(grandfatheredFor(w), VID, "sealed", w.key.epochPin(VID, 0), null, null);
  const { second, row, roster } = secondKeyRow(w, 1);
  const r = await check(w, row, { pins, fetchRosters: async () => [roster] });
  expect(r.trust).toMatchObject({ state: "waiting", replaced: true, own: false, acceptable: true, signer: { email: "alice@example.com", fingerprint: ident("alice").fingerprint } });
  expect(r.pins).toBe(pins);
  expect(ss.replacedSignedText("Team", "alice@example.com", false)).toBe(
    'The key of "Team" was replaced and signed by someone listed by your server as alice@example.com for the first time. Compare their fingerprint before you accept.',
  );
  expect(ss.replacedSignedText("Team", "alice@example.com", true)).toContain("signed by alice@example.com for the first time");
  const ok = await check(w, row, { pins, fetchRosters: async () => [roster], accept: tokenOf(r) });
  expect(ok.trust.state).toBe("ok");
  // pinsAccept: the new key, the old one retired, signed since the roster shown, with its hash.
  expect(ok.pins?.epochs?.[VID]).toMatchObject({ key_epoch: 1, key_id: second.keyId(VID), signed_since: 1, roster_version_max: 1, roster_hash: core.rosterHash(roster) });
  expect(ok.pins?.epochs?.[VID]?.retired).toHaveLength(1);
  second.free();
});

test("round 4 (own): a vault the account held with its own key wrap, now sealed by someone else, waits with the own-vault warning", async () => {
  const w = world();
  const pins = core.pinsObserve(null, { vault_id: VID, key_kind: "account", key: w.key.epochPin(VID, 0), roster_version: null, roster_hash: null, signed_share: false, paused: false }).pins;
  expect(pins.epochs?.[VID]?.own).toBe(true);
  const { second, row, roster } = secondKeyRow(w, 1);
  const r = await check(w, row, { pins, fetchRosters: async () => [roster] });
  expect(r.trust).toMatchObject({ state: "waiting", replaced: true, own: true, acceptable: true });
  expect(ss.ownVaultText("Team")).toBe('"Team" was your own vault. Your server now says someone else gave you a new key for it. Accept only if you shared this vault and expected a key change.');
  second.free();
});

test("round 4 (chain_hashes): a chain re-signed from version 1 that forks below the highest roster the account trusted is refused (roster_forked)", async () => {
  const w = world();
  const v2 = w.roster(w.v1, 0, "read");
  // The account trusted v2 (its hash pinned); this browser remembers no roster.
  const seen = core.pinsObserve(w.accepted(), {
    vault_id: VID,
    key_kind: "sealed",
    key: w.key.epochPin(VID, 0),
    roster_version: 2,
    roster_hash: core.rosterHash(v2),
    signed_share: true,
    paused: false,
  }).pins;
  // The server serves another v2 and a v3 on top of it: newer than the pinned version, so only the chain's hashes show the fork.
  const v2f = w.roster(w.v1, 0, "admin");
  const v3f = w.roster(v2f, 0, "write");
  const r = await check(w, signedRow(w, "write", { roster: v3f }), { pins: seen, fetchRosters: async () => [w.v1, v2f, v3f] });
  expect(why(r)).toBe("roster_forked");
  // The genuine chain to a v3 passes.
  const v3 = w.roster(v2, 0, "write");
  expect(why(await check(w, signedRow(w, "write", { roster: v3 }), { pins: seen, fetchRosters: async () => [w.v1, v2, v3] }))).toBe("ok");
});

test("round 4: accepting a re-share after leaving goes through pinsAccept: the tombstone is cleared and the re-join marked", async () => {
  const w = world();
  const left = core.pinsLeave(w.accepted(), VID, 1, 1500);
  const { second } = secondKeyRow(w, 1);
  const s = w.aliceSigner.sealAndSignShare(second, VID, w.bobSigner.publicIdentity(), "write", 1);
  const v2 = w.roster(w.v1, 1, "write", second);
  const row = sealedRow(s.sealed_key, "write", 1, { signature: s.signature, signer: w.signerSnap, signer_deleted: false }, v2);
  const r = await check(w, row, { pins: left, fetchRosters: async () => [w.v1, v2] });
  expect(r.trust).toMatchObject({ state: "waiting", rejoin: true, acceptable: true });
  const ok = await check(w, row, { pins: left, fetchRosters: async () => [w.v1, v2], accept: tokenOf(r) });
  expect(ok.trust.state).toBe("ok");
  expect(ok.pins?.left?.[VID]).toBeUndefined();
  expect(ok.pins?.epochs?.[VID]).toMatchObject({ key_epoch: 1, rejoined_at: 2 });
  second.free();
});

test("rule 4: accepting pins exactly the signer email shown; a row whose listed email changed since needs a new OK; an upgraded pin keeps its email and verified mark", async () => {
  const w = world();
  const carolAcct = accountOf("carol");
  const carol = carolAcct.openSigningIdentity(V.accounts[2]!.record);
  const ck = carolAcct.newVaultKey(VID).takeKey();
  const s = carol.sealAndSignShare(ck, VID, w.bobSigner.publicIdentity(), "write", 0);
  const members = [
    { ...carol.publicIdentity(), role: "owner" },
    { ...w.bobSigner.publicIdentity(), role: "write" },
  ];
  const r1 = carol.signRoster(ck, VID, null, 0, members, core.rosterReview(VID, null, carol.publicIdentity(), members, null).digest);
  const rowAs = (email: string) => sealedRow(s.sealed_key, "write", 0, { signature: s.signature, signer: w.snapshot(carol.publicIdentity(), email), signer_deleted: false }, r1);
  const shown = await check(w, rowAs(" Carol@Example.COM​"), { pins: null, fetchRosters: async () => [r1] });
  expect(shown.trust).toMatchObject({ state: "waiting", signer: { email: "carol@example.com" } });
  // The server lists another email for the same keys before the OK arrives: not accepted in the shown one's place.
  const other = await check(w, rowAs("ceo@example.com"), { pins: null, fetchRosters: async () => [r1], accept: tokenOf(shown) });
  expect(other.trust.state).toBe("waiting");
  const ok = await check(w, rowAs(" Carol@Example.COM​"), { pins: null, fetchRosters: async () => [r1], accept: tokenOf(shown) });
  expect(ok.trust.state).toBe("ok");
  expect(ok.pins?.pins.find((p) => p.user_id === who("carol").user_id)?.email).toBe("carol@example.com");
  // Upgraded (pinned legacy, now cross-signed): the pinned email and "verified" stay, whatever the server lists now.
  const legacyPinned = core.pinSet(w.accepted(), who("alice", true), "alice@example.com", true, 1000);
  const up = await check(w, signedRow(w, "write", { signer: w.snapshot(w.aliceSigner.publicIdentity(), "ceo@evil.example") }), { pins: legacyPinned });
  expect(up.trust).toMatchObject({ state: "ok", signer: { email: "alice@example.com", pinned: true, listedAs: "ceo@evil.example" } });
  expect(up.pins?.pins.find((p) => p.user_id === who("alice").user_id)).toMatchObject({ email: "alice@example.com", verified: true, signing_key: who("alice").signing_key });
  ck.free();
  carol.free();
});

test("rule 2: before the account's first signed sync finished here, an unsigned shared vault is held (neither accepted nor declined)", async () => {
  const w = world();
  const row = sealedRow(w.key.shareTo(VID, who("bob").public_key), "write", 0, null);
  const held = await check(w, row, { pins: null, holdUnsigned: true, memoryMissing: true });
  expect(held.trust).toMatchObject({ state: "refused", why: "checking", reason: ss.STILL_CHECKING_TEXT });
  expect(held.pins).toBe(null);
  // A signed one is still a consent (from the signer shown).
  expect((await check(w, signedRow(w), { pins: null, holdUnsigned: true })).trust.state).toBe("waiting");
});

test("normalizeEmail in one form: compared and pinned in full (never shortened for display), invisible characters and trailing dots gone", () => {
  for (const c of V.emails) expect(ss.normEmail(c.email), c.email).toBe(c.expected);
  const long = `${"a".repeat(150)}@example.com`;
  expect(ss.normEmail(long)).toBe(long);
  expect(ss.showEmail(long)).toHaveLength(128);
  expect(ss.normEmail(" ALICE@Example.COM.​")).toBe("alice@example.com");
});

test("M: only rows an offline copy showed as usable count as earlier (never waiting, held or refused ones; all when checks were off)", () => {
  const w = world();
  const ok = signedRow(w);
  const planted = { ...sealedRow("p", "write", 0, null), id: OTHER };
  const verdict = (row: import("../src/background/signed-sharing").SignedVaultRow, trust: import("../src/background/signed-sharing").Trust) => ({ row: ss.rowStamp(row), stamp: "s", trust });
  const copy = (trust?: Record<string, import("../src/background/signed-sharing").StoredVerdict>) => ({ vaults: [ok, planted], trust }) as never;
  expect(vault.usableVaultIds(copy({ [VID]: verdict(ok, { state: "ok" }), [OTHER]: verdict(planted, { state: "refused", reason: "", why: "checking" }) }))).toStrictEqual([VID]);
  expect(
    vault.usableVaultIds(
      copy({
        [VID]: verdict(ok, { state: "unsigned" }),
        [OTHER]: verdict(planted, { state: "waiting", name: "", rejoin: false, replaced: false, own: false, firstSigned: false, declinable: false, keyId: "k", acceptable: true, token: "t" }),
      }),
    ),
  ).toStrictEqual([VID]);
  // A verdict for another row than the one kept doesn't count.
  expect(vault.usableVaultIds(copy({ [VID]: verdict({ ...ok, role: "read" }, { state: "ok" }) }))).toStrictEqual([]);
  expect(vault.usableVaultIds(copy())).toStrictEqual([VID, OTHER]);
});

test("worker rule 1: an unsigned shared vault that can't be accepted stays locked with 'Ask the vault's owner to sign this vault.' and no Decline; one that may be accepted shows its key id", async () => {
  const { w } = await bobSignedIn();
  server.vaults.push({
    id: OTHER,
    wrapped_key: w.key.shareTo(OTHER, who("bob").public_key),
    key_kind: "sealed",
    role: "write",
    meta: "",
    key_epoch: 0,
    share: null,
    member_roster: null,
    member_roster_seq: 0,
  } as never);
  server.revision++;
  await vault.sync();
  const notice = vault.sharingNotice();
  expect(notice?.waiting).toMatchObject([{ vaultId: OTHER, acceptable: false, token: "", note: ss.ASK_OWNER_TEXT }]);
  expect(notice?.waiting[0]?.keyId).toBeUndefined();
  const { renderToStaticMarkup } = await import("react-dom/server");
  const { createElement } = await import("react");
  const { Notices } = await import("../src/popup/notices");
  const ctx = { signIns: null, state: { server: "https://vault.test" }, go: () => {}, notify: () => {} } as never;
  const html = renderToStaticMarkup(createElement(Notices, { ctx, data: { sharing: notice } as never, tabId: undefined }));
  expect(html).toContain("Ask the vault&#x27;s owner to sign this vault.");
  expect(notice?.waiting[0]?.text).toBe(ss.unsignedLockedText(""));
  expect(html).not.toContain("Decline");
  expect(html).not.toContain("Accept");
  // An unsigned vault that may be accepted (trust memory missing): the key id shown, still no Decline.
  await bobSignedIn({ pins: () => null, shared: unsignedShare });
  const n2 = vault.sharingNotice()!;
  expect(n2.waiting).toMatchObject([{ vaultId: VID, acceptable: true, keyId: w.key.keyId(VID), note: ss.UNSIGNED_LABEL }]);
  const html2 = renderToStaticMarkup(createElement(Notices, { ctx, data: { sharing: n2 } as never, tabId: undefined }));
  expect(html2).toContain(w.key.keyId(VID));
  expect(html2).not.toContain("Decline");
  // A signed one names its signer and may be declined in the web vault.
  const planted = carolsVault(w, OTHER, "carol@example.com");
  await bobSignedIn();
  server.vaults.push(planted.row as never);
  server.handlers[`GET /vaults/${OTHER}/rosters`] = () => ({ body: { rosters: [planted.roster], latest: 1, more: false } });
  server.revision++;
  await vault.sync();
  const html3 = renderToStaticMarkup(createElement(Notices, { ctx, data: { sharing: vault.sharingNotice() } as never, tabId: undefined }));
  expect(html3).toContain("Decline in the web vault");
  expect(html3).toContain(planted.fingerprint);
});

test("worker rule 2: while the first signed sync can't finish (identity upload failing), unsigned shared vaults are held, and the upload is tried again at every sync", async () => {
  const { stored } = await beforeSigning();
  server.handlers["PUT /account/identity"] = () => ({ status: 503, body: { error: "unavailable", message: "later" } });
  await unlockAgain();
  expect(names()).toStrictEqual(["Own"]);
  const notice = vault.sharingNotice();
  expect(notice?.waiting ?? []).toStrictEqual([]);
  expect(notice?.refused).toStrictEqual([{ vaultId: VID, reason: ss.STILL_CHECKING_TEXT }]);
  // No grandfathering (nor any consent) while it isn't known how the account's identity stands.
  expect(serverPins(stored).grandfathered ?? null).toBe(null);
  const puts = identityPuts().length;
  server.revision++;
  await vault.sync();
  expect(identityPuts().length).toBe(puts + 1);
});

test("worker: a 404 for the identity upload (the server doesn't sign) isn't tried again before the next unlock", async () => {
  await beforeSigning();
  server.handlers["PUT /account/identity"] = () => ({ status: 404, body: { error: "not_found", message: "not found" } });
  await unlockAgain();
  const puts = identityPuts().length;
  expect(puts).toBe(1);
  server.revision++;
  await vault.sync();
  expect(identityPuts()).toHaveLength(puts);
});

test("worker rule 6 / M: a vault planted while the first signed sync couldn't finish is never grandfathered later; only the vaults recorded when the identity was made are", async () => {
  const { stored, w } = await beforeSigning();
  // The upload is stored but its answer lost, and the server plants an unsigned shared vault meanwhile.
  server.handlers["PUT /account/identity"] = (req) => {
    (server.user as unknown as { identity: unknown }).identity = req.body;
    server.revision++;
    return { status: 502, body: { error: "bad_gateway", message: "lost" } };
  };
  server.vaults.push({
    id: OTHER,
    wrapped_key: w.key.shareTo(OTHER, who("bob").public_key),
    key_kind: "sealed",
    role: "write",
    meta: "",
    key_epoch: 0,
    share: null,
    member_roster: null,
    member_roster_seq: 0,
  } as never);
  server.handlers[`GET /vaults/${OTHER}/rosters`] = () => ({ body: { rosters: [], latest: 0, more: false } });
  await unlockAgain();
  expect(names()).toStrictEqual(["Own"]);
  // The next session: the server lists the identity made here; the planted vault (in this browser's copy, but held) isn't covered.
  await unlockAgain();
  expect(Object.keys(serverPins(stored).grandfathered ?? {}).sort()).toStrictEqual([OWN, VID].sort());
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()?.waiting).toMatchObject([{ vaultId: OTHER, acceptable: true, keyId: expect.any(String) }]);
  const memory = ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id);
  expect(memory?.pendingIdentities).toBeUndefined();
  expect(memory?.candidates).toBeUndefined();
});

test("rule 5: this browser's last-known pins are merged into a newer server copy (not only on 409), and written back when that adds anything", async () => {
  const { stored, bob, w } = await bobSignedIn();
  expect(stored.seq).toBe(2);
  // Another device (or the server) writes version 3 without what this browser knew (Alice's pin, the vault's epoch).
  const thin = core.pinsGrandfather(core.pinsSetOwnIdentity(null, ident("bob").hash), [], false);
  stored.pins = bob.sealKeyPins(thin, 3);
  stored.seq = 3;
  userField("key_pins_seq", 3);
  await vault.sync();
  expect(stored.seq).toBe(4);
  const merged = serverPins(stored);
  expect(merged.pins.map((p) => p.email)).toStrictEqual(["alice@example.com"]);
  expect(merged.epochs?.[VID]).toMatchObject({ key_id: w.key.keyId(VID), signed_since: 1 });
  expect(names()).toStrictEqual(["Own", "Team login"]);
});

test("Info: the trust-memory-missing state isn't shortened by a sync that couldn't check the vault", async () => {
  await bobSignedIn({ pins: () => null });
  expect(vault.sharingNotice()?.waiting).toMatchObject([{ vaultId: VID, acceptable: true }]);
  const ok = server.handlers[`GET /vaults/${VID}/rosters`]!;
  server.handlers[`GET /vaults/${VID}/rosters`] = () => ({ status: 500, body: { error: "internal", message: "boom" } });
  server.revision++;
  await vault.sync();
  expect(vault.sharingNotice()?.refused).toStrictEqual([{ vaultId: VID, reason: ss.CHECK_LATER_TEXT }]);
  expect(ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id)?.missing).toStrictEqual([VID]);
  server.handlers[`GET /vaults/${VID}/rosters`] = ok;
  server.revision++;
  await vault.sync();
  expect(vault.sharingNotice()?.waiting).toMatchObject([{ vaultId: VID, acceptable: true }]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.MEMORY_MISSING_TEXT);
});

test("rule 7: an unreadable trust memory never runs as none: shared vaults are refused, own vaults keep their checks (the server's pins, read only), nothing is written or accepted", async () => {
  const { stored } = await bobSignedIn();
  const seq = stored.seq;
  await storage.trustMemory.update("https://vault.test", V.accounts[1]!.id, () => "not a memory");
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  const notice = vault.sharingNotice();
  expect(notice?.warnings).toContain(ss.UNREADABLE_TEXT);
  expect(notice?.refused).toMatchObject([{ vaultId: VID, reason: ss.UNREADABLE_TEXT }]);
  expect(stored.seq).toBe(seq);
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/identity")).toStrictEqual([]);
  expect(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id)).toBe("not a memory");
  await expect(vault.trustNewKey(who("alice").user_id, ident("alice").fingerprint)).rejects.toThrow();
  await expect(vault.acceptSharedVault(VID, "t")).rejects.toThrow();
  // Own vaults keep their epoch and key id checks: the same key relabelled with a higher epoch is refused (not "new").
  (server.vaults[0] as unknown as { key_epoch: number }).key_epoch = 1;
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual([]);
  expect(
    vault
      .sharingNotice()
      ?.refused.map((r) => r.vaultId)
      .sort(),
  ).toStrictEqual([OWN, VID].sort());
});

test("rule 7: a sealed copy of the pins that doesn't open, with unsent changes, makes the memory unreadable; without them the server's copy (as new) replaces it", async () => {
  const { stored } = await bobSignedIn();
  const userId = V.accounts[1]!.id;
  const corrupt = (dirty: boolean) =>
    storage.trustMemory.update("https://vault.test", userId, (m) => ({ ...(ss.readMemory(m, userId) ?? ss.emptyMemory(userId)), pinsSealed: "broken", pinsDirty: dirty }));
  await corrupt(false);
  server.revision++;
  await vault.sync();
  // Round 5 Info: the server's copy at the same version doesn't repair it (only a strictly newer one does).
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.UNREADABLE_TEXT);
  // Another device writes a newer copy: that one replaces the broken copy.
  stored.pins = accountOf("bob").sealKeyPins(serverPins(stored), stored.seq + 1);
  stored.seq += 1;
  userField("key_pins_seq", stored.seq);
  await vault.sync();
  expect(names()).toStrictEqual(["Own", "Team login"]);
  expect(vault.sharingNotice()).toBe(null);
  expect(ss.readMemory(await storage.trustMemory.get("https://vault.test", userId), userId)?.pinsSealed).not.toBe("broken");
  const seq = stored.seq;
  await corrupt(true);
  server.revision++;
  await vault.sync();
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.UNREADABLE_TEXT);
  expect(stored.seq).toBe(seq);
});

// ------------------------------------------------------------------ review round 5

test("round 5 H: a copy this extension wrote with the checks off gives no grandfathering candidates: shares from before wait for consent (new browser)", async () => {
  // A server turned the checks off for this browser (no `signed_sharing`), then signs: nothing it served meanwhile counts.
  const { stored } = await beforeSigning(false);
  await unlockAgain();
  expect(identityPuts()).toHaveLength(1);
  expect(names()).toStrictEqual(["Own"]);
  expect(serverPins(stored).grandfathered).toStrictEqual({});
  const notice = vault.sharingNotice();
  expect(notice?.warnings).toStrictEqual([ss.NEW_DEVICE_TEXT]);
  expect(notice?.waiting).toMatchObject([{ vaultId: VID, acceptable: true, keyId: expect.any(String) }]);
  // usableVaultIds: a marked copy without verdicts gives none; an unmarked one (from before signed sharing) all.
  const rows = [{ id: VID }, { id: OWN }] as never;
  expect(vault.usableVaultIds({ vaults: rows, checks: "off" })).toStrictEqual([]);
  expect(vault.usableVaultIds({ vaults: rows })).toStrictEqual([VID, OWN]);
});

test("round 5 Info: a grandfathering candidate is bound to the key it had in the earlier copy: another key under that vault id waits for consent", async () => {
  const { stored, w } = await beforeSigning();
  // At the first signed sync the server serves another key under the shared vault's id.
  const second = aliceKey("secondKeyV2");
  server.vaults[1] = { ...server.vaults[1], wrapped_key: second.shareTo(VID, who("bob").public_key) } as never;
  await unlockAgain();
  expect(serverPins(stored).grandfathered?.[VID]).toBe(w.key.keyId(VID));
  expect(names()).toStrictEqual(["Own"]);
  // Unsigned and not covered by the trust-memory-missing state: locked until its owner signs it.
  expect(vault.sharingNotice()?.waiting).toMatchObject([{ vaultId: VID, acceptable: false, note: ss.ASK_OWNER_TEXT }]);
  // Session storage keeps the candidates with their key ids.
  expect(fake.session.data.get("earlier:a1")).toEqual(expect.arrayContaining([{ vault_id: VID, key_id: w.key.keyId(VID) }]));
  second.free();
});

test("round 5 H: a newer server copy of the key pins remembering another own identity is never merged or written; sharing pauses", async () => {
  const { stored, bob } = await bobSignedIn();
  expect(stored.seq).toBe(2);
  const before = serverPins(stored);
  // The server (or a device it gave a fake identity) writes version 3 remembering another own identity.
  const forged = core.pinsSetOwnIdentity(core.pinsGrandfather(null, [], false), ident("carol").hash);
  stored.pins = bob.sealKeyPins(forged, 3);
  stored.seq = 3;
  userField("key_pins_seq", 3);
  await vault.sync();
  // Nothing written (still the server's version 3), nothing merged either way, shared vaults refused, own vaults used.
  expect(stored.seq).toBe(3);
  expect(server.requests.filter((r) => r.method === "PUT" && r.path === "/account/key-pins")).toHaveLength(1);
  expect(names()).toStrictEqual(["Own"]);
  expect(vault.sharingNotice()?.warnings).toContain(ss.PAUSED_TEXT);
  // This browser's copy keeps its own identity and what it knew (not the server's).
  const memory = ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id)!;
  const mine = bob.openKeyPins(memory.pinsSealed!, memory.pinsSeq);
  expect(memory.pinsSeq).toBe(2);
  expect(mine.own_identity).toBe(before.own_identity);
  expect(mine.epochs?.[VID]).toStrictEqual(before.epochs?.[VID]);
});

test("round 5 M1: a newer server copy that only differs in a person's pin isn't rewritten from this browser's last-known copy (no write loop)", async () => {
  // This browser knows Dave by his old (legacy) keys; Alice's share is pinned and written at the first sync (version 2).
  const { stored, bob } = await bobSignedIn({
    pins: (w) => core.pinSet(core.pinsSetOwnIdentity(w.accepted(), ident("bob").hash), who("dave", true), "dave@example.com", false, 1000),
  });
  expect(stored.seq).toBe(2);
  // Another device later pinned Dave with his new keys, as verified (version 3).
  const newer = core.pinSet(serverPins(stored), who("dave"), "dave@example.com", true, 5000);
  stored.pins = bob.sealKeyPins(newer, 3);
  stored.seq = 3;
  userField("key_pins_seq", 3);
  await vault.sync();
  // The server's later decision stands: nothing written back (`mergePins` would have put the old keys back).
  expect(stored.seq).toBe(3);
  expect(serverPins(stored).pins.find((p) => p.email === "dave@example.com")).toMatchObject({ identity: ident("dave").hash, verified: true });
  expect(names()).toStrictEqual(["Own", "Team login"]);
  // This browser follows it.
  const memory = ss.readMemory(await storage.trustMemory.get("https://vault.test", V.accounts[1]!.id), V.accounts[1]!.id)!;
  expect(memory.pinsSeq).toBe(3);
  expect(memory.pinsDirty).toBe(false);
  expect(bob.openKeyPins(memory.pinsSealed!, 3).pins.find((p) => p.email === "dave@example.com")?.identity).toBe(ident("dave").hash);
});

test("round 5 L: while the trust memory can't be read, a server copy below the version this browser session opened isn't used", async () => {
  const { stored } = await bobSignedIn();
  expect(stored.seq).toBe(2);
  expect(fake.session.data.get("pinsFloor:a1")).toBe(2);
  // The memory record breaks, and the server rolls its copy back to version 1.
  await storage.trustMemory.update("https://vault.test", V.accounts[1]!.id, () => ({ broken: true }) as never);
  const old = core.pinsSetOwnIdentity(null, ident("bob").hash);
  stored.pins = accountOf("bob").sealKeyPins(old, 1);
  stored.seq = 1;
  userField("key_pins_seq", 1);
  const fetched = () => server.requests.filter((r) => r.method === "GET" && r.path === "/account/key-pins").length;
  const n = fetched();
  await vault.sync();
  expect(fetched()).toBe(n);
  expect(vault.sharingNotice()?.warnings).toContain(ss.UNREADABLE_TEXT);
  // Own vaults still checked against what this session last used (its own pins), shared ones refused.
  expect(names()).toStrictEqual(["Own"]);
});

test("round 5 (iOS H): kept keys whose bundle the core doesn't authenticate are never restored; a sync with a swapped bundle is never kept", async () => {
  await bobSignedIn();
  // A sync answer whose account bundle isn't this account's: refused, nothing kept.
  server.bundle = { account_id: V.accounts[1]!.id, secret_key_enabled: false, swapped: true };
  server.revision++;
  await expect(vault.sync()).rejects.toThrow(ss.WRONG_ACCOUNT_TEXT);
  expect((await storage.syncCache.get("a1"))?.bundle).not.toHaveProperty("swapped");
  expect((await storage.session.get("a1"))?.bundle).not.toHaveProperty("swapped");
  // Session keys kept with a swapped bundle (from disk, timeout "never"): dropped; the master password is asked for.
  await vault.lockAll();
  const kept = { ...sessionFor("bob"), bundle: { account_id: V.accounts[1]!.id, secret_key_enabled: false, swapped: true } };
  const l = (await fake.local.get(["accounts", "settings"])) as { accounts: Record<string, object>; settings?: object };
  await fake.local.set({ accounts: { ...l.accounts, a1: { ...l.accounts.a1, persistedKeys: kept } }, settings: { ...(l.settings ?? {}), vaultTimeout: "never" } });
  expect(await vault.ensureUnlocked()).toBe(false);
  expect(await storage.session.get("a1")).toBe(null);
  expect((await storage.local.account("a1")).data?.persistedKeys ?? null).toBe(null);
});

test("round 5: a first signature on a vault the account holds needs one OK (first_signed, never declinable); accepting pins the signer", async () => {
  const w = world();
  // Bob had the vault from before (grandfathered, unsigned) at epoch 0; Alice signs it now at the same key.
  const pins = core.pinsRecordRotation(grandfatheredFor(w), VID, "sealed", w.key.epochPin(VID, 0), null, null);
  const r = await check(w, signedRow(w), { pins });
  expect(r.trust).toMatchObject({ state: "waiting", firstSigned: true, replaced: false, declinable: false, acceptable: true, signer: { email: "alice@example.com" } });
  expect(r.pins).toBe(pins);
  expect(ss.firstSignedText("Team", "alice@example.com", true)).toBe('"Team" was signed for the first time, by alice@example.com. Compare their fingerprint before you accept.');
  expect(ss.firstSignedText("Team", "alice@example.com", false)).toContain("someone listed by your server as alice@example.com");
  const ok = await check(w, signedRow(w), { pins, accept: tokenOf(r) });
  expect(ok.trust.state).toBe("ok");
  expect(ok.pins?.epochs?.[VID]).toMatchObject({ key_id: w.key.keyId(VID), signed_since: 1, roster_version_max: 1, roster_hash: core.rosterHash(w.v1) });
  expect(ok.pins?.pins.map((p) => p.email)).toContain("alice@example.com");
});
