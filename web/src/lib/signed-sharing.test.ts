/**
 * Signed sharing flows (`signed-sharing.ts`) with the real core against a fake server: the signing identity at unlock
 * (own identity memory, pause), "me" from the core, key pins (compare-and-swap, merge, rollback, saved locally on every
 * change), every check of a vault row and an invitation and the attacks they refuse (planted rows → consent, epoch
 * rollbacks, forged signers, stripped rosters, tombstones, caps), the verdict cache, and the member review before
 * signing (version 1, missing people, automatic flows).
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import { loadCore, signedVectors, vectorAccounts, type SignedVectors } from "./test-core";

const h = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(
      public status: number,
      public code: string,
      message: string,
    ) {
      super(message);
    }
  }
  const server = {
    /** The caller's user id. */
    user: "",
    identity: new Map<string, unknown>(),
    pins: new Map<string, { key_pins: string | null; seq: number }>(),
    rosters: new Map<string, string[]>(),
    /** Rosters per page (the real server sends 100). */
    pageSize: 100,
    calls: [] as string[],
    /** Next request fails like this once (by path prefix). */
    fail: null as null | { path: string; error: Error },
    /** Next request to this path is handled, but its answer is lost (a network error after the server stored it). */
    lose: null as null | string,
  };
  async function api(path: string, opts: { method?: string; body?: unknown } = {}): Promise<unknown> {
    const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
    server.calls.push(`${method} ${path}`);
    if (server.fail && path.startsWith(server.fail.path)) {
      const e = server.fail.error;
      server.fail = null;
      throw e;
    }
    if (path === "/account/identity" && method === "PUT") {
      const have = server.identity.get(server.user);
      if (have && JSON.stringify(have) !== JSON.stringify(opts.body)) throw new ApiError(409, "identity_exists", "exists");
      server.identity.set(server.user, opts.body);
      if (server.lose === path) {
        server.lose = null;
        throw new Error("network");
      }
      return { ok: true, created: !have };
    }
    if (path === "/account/key-pins") {
      const have = server.pins.get(server.user) ?? { key_pins: null, seq: 0 };
      if (method === "GET") return have;
      const b = opts.body as { key_pins: string; seq: number };
      if (b.seq !== have.seq + 1) throw new ApiError(409, "key_pins_changed", "changed");
      server.pins.set(server.user, { key_pins: b.key_pins, seq: b.seq });
      return { seq: b.seq };
    }
    const m = /^\/vaults\/([^/]+)\/rosters\?after=(\d+)$/.exec(path);
    if (m) {
      const list = server.rosters.get(decodeURIComponent(m[1])) ?? [];
      const page = list.slice(Number(m[2]), Number(m[2]) + server.pageSize);
      return { rosters: page, latest: list.length, more: Number(m[2]) + page.length < list.length };
    }
    throw new ApiError(404, "not_found", `no route ${method} ${path}`);
  }
  return { server, ApiError, api };
});

vi.mock("./api", () => ({
  api: h.api,
  ApiError: h.ApiError,
  hasErrorCode: (e: unknown, code: string) => e instanceof h.ApiError && e.code === code,
}));

import {
  CHECK_LATER,
  KeyChangedError,
  RaceError,
  ReviewNeededError,
  acceptConsent,
  acceptInvitationTrust,
  CHANGED_SINCE_SHOWN,
  checksRemembered,
  endSigning,
  noteVaultsSeen,
  flushPins,
  identityFingerprint,
  markLeft,
  personState,
  pinReviewed,
  pinsNotice,
  planChange,
  prepareSigning,
  sharedEvidence,
  signingProblem,
  signingReady,
  trustPerson,
  useStore,
  verifiedRoster,
  verifySnapshot,
  type Consent,
  type SignedInvitationRow,
  type SignedVaultRow,
  type VaultVerdict,
} from "./signed-sharing";
import {
  ACCOUNT_MISMATCH,
  NEW_DEVICE,
  seenKey,
  PINS_ROLLED_BACK,
  SHARING_PAUSED,
  TOO_MANY_CHANGES,
  TRUST_MEMORY_MISSING,
  VAULT_LEFT,
  VAULT_REFUSED,
  memoryKey,
  namesFromRows,
  pinsKey,
  readMemory,
  trustScope,
  type MembersAnswer,
  type PublicIdentity,
} from "./signing";

let v: SignedVectors;
let accounts: ReturnType<typeof vectorAccounts>;
let signers: Map<string, core.SigningIdentity>;
const local = new Map<string, string>();
const EMAIL: Record<string, string> = { alice: "alice@example.com", bob: "bob@example.com", carol: "carol@example.com", dave: "dave@example.com" };
const store = { get: (k: string) => local.get(k) ?? null, set: (k: string, val: string | null) => void (val === null ? local.delete(k) : local.set(k, val)) };

beforeAll(async () => {
  await loadCore();
  v = await signedVectors();
  accounts = vectorAccounts(v);
  signers = new Map([...accounts].map(([name, a]) => [name, a.account.openSigningIdentity(a.record)]));
  useStore(store);
});

beforeEach(() => {
  endSigning();
  local.clear();
  h.server.user = "";
  h.server.identity = new Map(v.accounts.map((a) => [a.id, a.record]));
  h.server.pins = new Map();
  h.server.rosters = new Map();
  h.server.pageSize = 100;
  h.server.calls = [];
  h.server.fail = null;
  h.server.lose = null;
});

const acct = (name: string) => accounts.get(name)!;
const id = (name: string) => acct(name).id;
const pub = (name: string) => v.identities.find((i) => i.name === name)!.publicIdentity as PublicIdentity;
const VID = () => v.vault.id;
const vaultKey = () => acct("alice").account.openVaultKey(VID(), v.vault.wrappedKey, "account", 0, true);
const scope = (name: string) => trustScope("", id(name));

/** Unlock as `name`: the session's identity and key pins, as `vault.ts` does at every sync. */
async function as(name: string, user: { identity?: unknown; key_pins_seq?: unknown; id?: string } = {}) {
  endSigning();
  const a = acct(name);
  h.server.user = a.id;
  await prepareSigning(
    a.account,
    {
      id: user.id ?? a.id,
      identity: "identity" in user ? user.identity : (h.server.identity.get(a.id) ?? null),
      key_pins_seq: user.key_pins_seq ?? h.server.pins.get(a.id)?.seq ?? 0,
    },
    async () => ({ identity: h.server.identity.get(a.id) ?? null }),
  );
}

type Members = [string, string][];
const inputs = (members: Members): core.RosterMemberInput[] => members.map(([n, role]) => ({ ...pub(n), role, email: EMAIL[n] }));

/** Sign the next roster of the vault (by `signer`, after `previous`), as an app would after the review. */
function signRoster(signer: string, previous: string | null, epoch: number, members: Members, key = vaultKey()): string {
  const s = signers.get(signer)!;
  const review = core.rosterReview(VID(), previous, s.publicIdentity(), inputs(members), null);
  return s.signRoster(key, VID(), previous, epoch, inputs(members), review.digest);
}

const shareOf = (signer: string, signature: string, extra: Record<string, unknown> = {}) => ({
  signature,
  signer: { ...pub(signer), email: EMAIL[signer], name: signer, ...extra },
  signer_deleted: false,
});

/** Alice's vault shared with `to` (signed by alice at epoch 0); the server holds the rosters. */
function sharedRow(to: string, role: string, members: Members = [["alice", "owner"], [to, role]], key = vaultKey()): SignedVaultRow {
  const r1 = signRoster("alice", null, 0, members, key);
  h.server.rosters.set(VID(), [r1]);
  const share = signers.get("alice")!.sealAndSignShare(key, VID(), pub(to), role, 0);
  return { id: VID(), role, wrapped_key: share.sealed_key, key_kind: "sealed", key_epoch: 0, member_roster: r1, member_roster_seq: 1, share: shareOf("alice", share.signature) };
}

const invitationOf = (row: SignedVaultRow): SignedInvitationRow => ({
  vault_id: row.id,
  role: row.role,
  wrapped_key: row.wrapped_key,
  key_epoch: row.key_epoch,
  share: row.share,
  member_roster: row.member_roster,
});

async function verdict(row: SignedVaultRow): Promise<VaultVerdict> {
  return (await verifySnapshot([row], []))!.vaults.get(row.id)!;
}

/** Bob accepts the vault (as through its invitation) so later syncs admit it. */
async function bobAccepts(row: SignedVaultRow) {
  await as("bob");
  const inv = (await verifySnapshot([], [invitationOf(row)]))!.invitations.get(row.id)!;
  expect(inv.kind).toBe("signed");
  if (inv.kind === "signed") acceptInvitationTrust(row.id, inv);
}

describe("signing identity at unlock", () => {
  it("makes one and uploads it when the account has none, and remembers it as its own", async () => {
    h.server.identity.set(id("alice"), null);
    await as("alice", { identity: null });
    expect(signingReady()).toBe(true);
    expect(h.server.identity.get(id("alice"))).toMatchObject({ x25519_signature: expect.any(String) });
    expect(identityFingerprint()).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/);
    expect(readMemory(store, scope("alice")).own).toBeTruthy();
  });

  it("opens the stored one when another device uploaded first (409 identity_exists)", async () => {
    h.server.identity.set(id("alice"), acct("alice").record);
    await as("alice", { identity: null });
    expect(signingReady()).toBe(true);
    expect(identityFingerprint()).toBe(v.identities.find((i) => i.name === "alice")!.fingerprint);
  });

  it("refuses a sync for another account than the one unlocked (H1)", async () => {
    await expect(as("alice", { id: id("bob") })).rejects.toThrow(ACCOUNT_MISMATCH);
  });

  it("pauses sharing when the server lists keys that aren't this account's", async () => {
    await as("alice", { identity: acct("bob").record });
    expect(signingReady()).toBe(false);
    expect(signingProblem()).toBe(SHARING_PAUSED);
    expect(identityFingerprint()).toBeNull();
  });

  it("pauses when the identity it had disappears, or another one is listed later (L4)", async () => {
    await as("alice");
    expect(signingReady()).toBe(true);
    // Next unlock: the server lists none. No second identity is made.
    await as("alice", { identity: null });
    expect(signingProblem()).toBe(SHARING_PAUSED);
    expect(h.server.calls.filter((c) => c === "PUT /account/identity")).toHaveLength(0);
    // A malformed record pauses too.
    await as("alice", { identity: { signing_key: "x" } });
    expect(signingProblem()).toBe(SHARING_PAUSED);
  });

  it("refuses every sealed vault while paused, but keeps own vaults (aligned with the extension)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    await flushPins();
    await as("bob", { identity: acct("carol").record });
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: SHARING_PAUSED });
  });
});

describe("vault rows", () => {
  it("holds a signed vault the account never accepted for consent (planted row, H2/H3), and uses it after accepting", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    const first = await verdict(row);
    expect(first).toMatchObject({ status: "consent", consent: { rejoin: false, signer: { label: "alice@example.com", pin: "new" } } });
    // Nothing was pinned: the signer is pinned only when the user accepts (M1).
    expect(personState(pub("alice")).status).toBe("new");
    acceptConsent((first as { consent: Consent }).consent);
    expect(personState(pub("alice")).status).toBe("match");
    expect(await verdict(row)).toMatchObject({ status: "ok", trust: { kind: "signed", signer: { label: "alice@example.com" } }, rosterSeq: 1 });
    expect(verifiedRoster(VID())).toBe(row.member_roster);
  });

  it("can't accept an unsigned vault the account never accepted (once its trust memory is in place)", async () => {
    const key = vaultKey();
    const row: SignedVaultRow = { id: VID(), role: "write", wrapped_key: key.shareTo(VID(), pub("bob").public_key), key_kind: "sealed", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null };
    // First unlock: an identity from before but no key pins (trust memory missing): unsigned vaults may be accepted then.
    await as("bob");
    const missing = await verdict(row);
    expect(missing).toMatchObject({ status: "consent", consent: { signer: null, unsignedAllowed: true } });
    expect(pinsNotice()).toBe(TRUST_MEMORY_MISSING);
    await flushPins();
    // Next unlock: the (empty) grandfathered list is written. The vaults that waited then still may be accepted here
    // (device memory `missing`), but one the server adds later is decline only.
    await as("bob");
    expect(await verdict(row)).toMatchObject({ status: "consent", consent: { unsignedAllowed: true } });
    const otherKey = acct("alice").account.newVaultKey("vault-planted-later").takeKey();
    const later: SignedVaultRow = { ...row, id: "vault-planted-later", wrapped_key: otherKey.shareTo("vault-planted-later", pub("bob").public_key) };
    otherKey.free();
    const c = (await verifySnapshot([row, later], []))!.vaults.get(later.id)!;
    expect(c).toMatchObject({ status: "consent", consent: { signer: null, unsignedAllowed: false, replaced: false } });
    expect(() => acceptConsent((c as { consent: Consent }).consent)).toThrow(/isn't signed/);
  });

  it("asks before using a key an app that doesn't sign replaced on a grandfathered vault (consent replaced)", async () => {
    const key = vaultKey();
    const unsigned: SignedVaultRow = { id: VID(), role: "write", wrapped_key: key.shareTo(VID(), pub("bob").public_key), key_kind: "sealed", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null };
    h.server.identity.set(id("bob"), null);
    noteVaultsSeen(acct("bob").account, [VID()]); // an earlier session on this device
    await as("bob", { identity: null });
    expect(await verdict(unsigned)).toMatchObject({ status: "ok", trust: { kind: "unsigned" } });
    const fresh = acct("alice").account.newVaultKey(VID()).takeKey();
    const replaced = { ...unsigned, key_epoch: 1, wrapped_key: fresh.shareTo(VID(), pub("bob").public_key) };
    const c = await verdict(replaced);
    expect(c).toMatchObject({ status: "consent", consent: { replaced: true } });
    acceptConsent((c as { consent: Consent }).consent);
    expect(await verdict(replaced)).toMatchObject({ status: "ok", trust: { kind: "unsigned" } });
  });

  it("grandfathers only the unsigned shares present when this unlock made the identity", async () => {
    const key = vaultKey();
    const unsigned: SignedVaultRow = { id: VID(), role: "write", wrapped_key: key.shareTo(VID(), pub("bob").public_key), key_kind: "sealed", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null };
    h.server.identity.set(id("bob"), null);
    noteVaultsSeen(acct("bob").account, [VID()]); // an earlier session on this device
    await as("bob", { identity: null });
    // Bob's new identity: the share to his legacy identity still verifies.
    expect(await verdict(unsigned)).toMatchObject({ status: "ok", trust: { kind: "unsigned" } });
  });

  it("warns and grandfathers nothing when the identity exists but the key pins are missing", async () => {
    const key = vaultKey();
    const unsigned: SignedVaultRow = { id: VID(), role: "write", wrapped_key: key.shareTo(VID(), pub("bob").public_key), key_kind: "sealed", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null };
    await as("bob");
    expect(await verdict(unsigned)).toMatchObject({ status: "consent" });
    expect(pinsNotice()).toBe(TRUST_MEMORY_MISSING);
  });

  it("refuses a role the share and roster don't give", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    expect(await verdict({ ...row, role: "admin" })).toMatchObject({ status: "refused", reason: VAULT_REFUSED });
  });

  it("refuses a share signed by someone the roster doesn't make an owner or admin", async () => {
    const key = vaultKey();
    const r1 = signRoster("alice", null, 0, [["alice", "owner"], ["bob", "write"], ["carol", "write"]], key);
    h.server.rosters.set(VID(), [r1]);
    const share = signers.get("carol")!.sealAndSignShare(key, VID(), pub("bob"), "write", 0);
    const row: SignedVaultRow = { id: VID(), role: "write", wrapped_key: share.sealed_key, key_kind: "sealed", key_epoch: 0, member_roster: r1, member_roster_seq: 1, share: shareOf("carol", share.signature) };
    await as("bob");
    expect(await verdict(row)).toMatchObject({ status: "refused" });
  });

  it("refuses a vault key the server sealed itself (the roster commits to another key)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    const other = acct("alice").account.newVaultKey(VID()).takeKey();
    expect(await verdict({ ...row, wrapped_key: other.shareTo(VID(), pub("bob").public_key) })).toMatchObject({ status: "refused" });
  });

  it("refuses a stripped roster or share once the vault was seen signed (rollback)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    expect(await verdict(row)).toMatchObject({ status: "ok" });
    expect(await verdict({ ...row, member_roster: null, member_roster_seq: 0 })).toMatchObject({ status: "refused" });
    expect(await verdict({ ...row, share: null })).toMatchObject({ status: "refused" });
  });

  it("refuses a row without a key epoch (missing_epoch)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    expect(await verdict({ ...row, key_epoch: undefined })).toMatchObject({ status: "refused" });
  });

  it("refuses an older key epoch than the account's apps saw, also on a vault without a roster (H4)", async () => {
    await as("alice");
    const own: SignedVaultRow = { id: VID(), role: "owner", wrapped_key: v.vault.wrappedKey, key_kind: "account", key_epoch: 3, member_roster: null, member_roster_seq: 0, share: null };
    expect(await verdict(own)).toMatchObject({ status: "ok", trust: { kind: "own" } });
    // The same key served as an older epoch, then relabelled as newer: both refused (key ids).
    expect(await verdict({ ...own, key_epoch: 2 })).toMatchObject({ status: "refused" });
    expect(await verdict({ ...own, key_epoch: 4 })).toMatchObject({ status: "refused" });
  });

  it("stops at a signer whose keys changed, until the user trusts exactly the new key shown", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    // The server now lists another identity under Alice's user id (Carol's keys).
    const forged = { ...row, share: { ...shareOf("alice", "x"), signer: { ...pub("carol"), user_id: id("alice"), email: EMAIL.alice, name: "alice" } } };
    const out = await verdict(forged);
    expect(out.status).toBe("refused");
    // Mark as verified / trust only for the identity shown (hash compared).
    expect(() => trustPerson(pub("alice"), "alice@example.com", { mode: "verify", shownHash: "other" })).toThrow(/changed since/);
    const info = core.verifyIdentity(pub("alice"));
    trustPerson(pub("alice"), "alice@example.com", { mode: "verify", shownHash: info.hash });
    expect(personState(pub("alice")).verified).toBe(true);
  });

  it("refuses a new account using an email already pinned for another (email_conflict)", async () => {
    await as("bob");
    trustPerson(pub("alice"), "alice@example.com", { mode: "trust", shownHash: core.verifyIdentity(pub("alice")).hash });
    // Dave's account, listed with Alice's email, signs a share for a vault.
    const key = vaultKey();
    const r1 = signRoster("dave", null, 0, [["dave", "owner"], ["bob", "write"]], key);
    h.server.rosters.set(VID(), [r1]);
    const share = signers.get("dave")!.sealAndSignShare(key, VID(), pub("bob"), "write", 0);
    const planted: SignedVaultRow = {
      id: VID(),
      role: "write",
      wrapped_key: share.sealed_key,
      key_kind: "sealed",
      key_epoch: 0,
      member_roster: r1,
      member_roster_seq: 1,
      share: shareOf("dave", share.signature, { email: " ALICE@example.com" }),
    };
    expect(await verdict(planted)).toMatchObject({ status: "refused", changed: { status: "email_conflict" } });
  });

  it("caches a verdict while the row and its state stay the same, and checks again when the remembered roster or pins change (L5)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    await verdict(row);
    h.server.calls = [];
    expect(await verdict(row)).toMatchObject({ status: "ok" });
    expect(h.server.calls).toEqual([]);
    // Another tab forgets the roster (cleared storage for the vault): checked again, roster fetched again.
    const m = JSON.parse(local.get(memoryKey(scope("bob")))!);
    delete m.vaults[VID()];
    local.set(memoryKey(scope("bob")), JSON.stringify(m));
    await verdict(row);
    expect(h.server.calls.some((c) => c.includes("/rosters?after=0"))).toBe(true);
  });

  it("doesn't use a vault whose roster history can't be fetched, and checks again later", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    h.server.fail = { path: `/vaults/${VID()}/rosters`, error: new Error("offline") };
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: CHECK_LATER });
    expect((await verdict(row)).status).toBe("consent");
  });

  it("refuses a roster history beyond the caps (M2)", async () => {
    const key = vaultKey();
    const list: string[] = [];
    let prev: string | null = null;
    for (let i = 0; i < 12; i++) {
      prev = signRoster("alice", prev, 0, [["alice", "owner"], ["bob", i % 2 ? "read" : "write"]], key);
      list.push(prev);
    }
    h.server.rosters.set(VID(), list);
    h.server.pageSize = 1; // 12 pages > 10
    const share = signers.get("alice")!.sealAndSignShare(key, VID(), pub("bob"), "write", 0);
    await as("bob");
    const row: SignedVaultRow = { id: VID(), role: "write", wrapped_key: share.sealed_key, key_kind: "sealed", key_epoch: 0, member_roster: prev, member_roster_seq: 12, share: shareOf("alice", share.signature) };
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: TOO_MANY_CHANGES });
  });

  it("refuses a vault the account left (tombstone), until it's shared again with a newer roster", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    await verdict(row);
    markLeft(VID());
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: VAULT_LEFT });
  });

  it("writes the key pins once, saved locally at every change (L4)", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    expect(local.get(pinsKey(scope("bob")))).toContain('"dirty":true');
    await verdict(row);
    await flushPins();
    expect(h.server.calls.filter((c) => c === "PUT /account/key-pins")).toHaveLength(1);
    expect(local.get(pinsKey(scope("bob")))).toContain('"dirty":false');
  });

  it("keeps trust memory per server and account", async () => {
    await as("alice");
    expect(local.has(memoryKey(scope("alice")))).toBe(true);
    expect(checksRemembered(acct("alice").account, { user: {}, vaults: [], invitations: [] })).toBe(true);
    expect(checksRemembered(acct("carol").account, { user: {}, vaults: [], invitations: [] })).toBe(false);
    expect(checksRemembered(acct("carol").account, { user: { key_pins_seq: 1 }, vaults: [], invitations: [] })).toBe(true);
  });
});

describe("key pins", () => {
  it("merges with another device's write (409 key_pins_changed) and writes the next version", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    h.server.pins.set(id("bob"), { key_pins: acct("bob").account.sealKeyPins({ version: 1, pins: [] }, 1), seq: 1 });
    await flushPins();
    expect(h.server.pins.get(id("bob"))?.seq).toBe(2);
    const stored = acct("bob").account.openKeyPins(h.server.pins.get(id("bob"))!.key_pins!, 2);
    expect(stored.epochs?.[VID()]).toBeTruthy();
  });

  it("keeps this device's newer list when the server sends an older one", async () => {
    await as("alice");
    await verifySnapshot([], []);
    await flushPins();
    expect(h.server.pins.get(id("alice"))?.seq).toBe(1);
    h.server.pins.set(id("alice"), { key_pins: null, seq: 0 });
    await as("alice", { key_pins_seq: 0 });
    expect(pinsNotice()).toBe(PINS_ROLLED_BACK);
  });
});

describe("invitations", () => {
  it("shows a signed invitation with its signer's fingerprint and pin state, pinning nothing until accepted", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    const inv = (await verifySnapshot([], [invitationOf(row)]))!.invitations.get(VID())!;
    expect(inv).toMatchObject({ kind: "signed", signer: { label: "alice@example.com", pin: "new", fingerprint: expect.any(String) }, rosterVersion: 1 });
    expect(personState(pub("alice")).status).toBe("new");
  });

  it("refuses an unsigned one (decline only)", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    expect((await verifySnapshot([], [{ ...invitationOf(row), share: null }]))!.invitations.get(VID())).toEqual({ kind: "unsigned" });
  });

  it("refuses a forged invitation: signed by someone the roster doesn't list as owner or admin", async () => {
    const row = sharedRow("bob", "write");
    const key = vaultKey();
    const forged = signers.get("carol")!.sealAndSignShare(key, VID(), pub("bob"), "write", 0);
    await as("bob");
    const inv = (await verifySnapshot([], [{ ...invitationOf(row), wrapped_key: forged.sealed_key, share: shareOf("carol", forged.signature) }]))!.invitations.get(VID());
    expect(inv).toMatchObject({ kind: "refused" });
  });

  it("refuses an invitation whose signature doesn't verify", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    const inv = (await verifySnapshot([], [{ ...invitationOf(row), role: "admin" }]))!.invitations.get(VID());
    expect(inv).toMatchObject({ kind: "refused" });
  });
});

describe("member review before signing", () => {
  const members = (list: Members, roster: string | null, epoch = 0): MembersAnswer => ({
    members: list.map(([n, role]) => ({ ...pub(n), email: EMAIL[n], name: n, role: role as "read", key_kind: n === "alice" ? "account" : "sealed", share: null })),
    keyEpoch: epoch,
    roster,
    rosterSeq: roster ? 1 : 0,
  });
  const ownRow = (roster: string | null): SignedVaultRow => ({ id: VID(), role: "owner", wrapped_key: v.vault.wrappedKey, key_kind: "account", key_epoch: 0, member_roster: roster, member_roster_seq: roster ? 1 : 0, share: null });
  const plan = (answer: MembersAnswer, extra: Partial<Parameters<typeof planChange>[0]> = {}) =>
    planChange({ vaultId: VID(), answer, rows: inputs(answer.members.map((m) => [Object.keys(EMAIL).find((n) => id(n) === m.user_id)!, m.role])), keyEpoch: 0, what: "didn't change the key", nameOf: namesFromRows(answer.members), ...extra });

  it("asks for the version-1 review of every member (H4), and accepts exactly the confirmed list", async () => {
    await as("alice");
    await verifySnapshot([ownRow(null)], []);
    const answer = members([["alice", "owner"], ["bob", "write"]], null);
    let review: ReviewNeededError | null = null;
    try {
      plan(answer);
    } catch (e) {
      review = e as ReviewNeededError;
    }
    expect(review).toBeInstanceOf(ReviewNeededError);
    expect(review!.review).toMatchObject({ first: true, members: [{ label: "You" }, { label: "bob@example.com", pin: "new" }] });
    // Confirming another list (another digest) isn't enough.
    expect(() => plan(answer, { confirmed: { digest: "x", missing: [] } })).toThrow(ReviewNeededError);
    expect(plan(answer, { confirmed: { digest: review!.review.digest, missing: [] } }).trusted).toBeNull();
  });

  it("never creates version 1 in an automatic flow", async () => {
    await as("alice");
    await verifySnapshot([ownRow(null)], []);
    expect(() => plan(members([["alice", "owner"], ["bob", "write"]], null), { automatic: true })).toThrow(/didn't replace its key automatically/);
  });

  it("asks per missing user id, by name, never by raw id (L1/L2)", async () => {
    const r1 = signRoster("alice", null, 0, [["alice", "owner"], ["bob", "write"], ["carol", "read"]]);
    h.server.rosters.set(VID(), [r1]);
    await as("alice");
    await verifySnapshot([ownRow(r1)], []);
    const answer = members([["alice", "owner"], ["bob", "write"]], r1);
    let review: ReviewNeededError | null = null;
    try {
      plan(answer, { confirmed: { digest: "whatever", missing: [] } });
    } catch (e) {
      review = e as ReviewNeededError;
    }
    expect(review!.review.missing).toEqual([{ userId: id("carol"), role: "read", label: "Someone who was in this vault" }]);
    expect(JSON.stringify(review!.review)).not.toContain(`"label":"${id("carol")}"`);
    // Confirming the digest without Carol's id isn't enough.
    expect(() => plan(answer, { confirmed: { digest: review!.review.digest, missing: [] } })).toThrow(ReviewNeededError);
    expect(plan(answer, { confirmed: { digest: review!.review.digest, missing: [id("carol")] } }).trusted).toBe(r1);
    // The removed member is expected to be missing.
    expect(plan(members([["alice", "owner"], ["bob", "write"]], r1), { removed: id("carol") }).trusted).toBe(r1);
  });

  it("stops when the server lists someone the trusted roster doesn't, and when its version isn't the trusted one (L3)", async () => {
    const r1 = signRoster("alice", null, 0, [["alice", "owner"], ["bob", "write"]]);
    h.server.rosters.set(VID(), [r1]);
    await as("alice");
    await verifySnapshot([ownRow(r1)], []);
    expect(() => plan(members([["alice", "owner"], ["bob", "write"], ["carol", "read"]], r1))).toThrow(/doesn't: carol@example.com/);
    expect(() => plan({ ...members([["alice", "owner"], ["bob", "write"]], r1), rosterSeq: 2 })).toThrow(RaceError);
    expect(() => plan(members([["alice", "owner"], ["bob", "write"]], r1), { keyEpoch: 1 })).toThrow(RaceError);
  });

  it("stops at a member whose keys changed", async () => {
    const r1 = signRoster("alice", null, 0, [["alice", "owner"], ["bob", "write"]]);
    h.server.rosters.set(VID(), [r1]);
    await as("alice");
    await verifySnapshot([ownRow(r1)], []);
    trustPerson(pub("bob"), "bob@example.com", { mode: "trust", shownHash: core.verifyIdentity(pub("bob")).hash });
    const answer = members([["alice", "owner"], ["bob", "write"]], r1);
    // The server now lists Bob without his signing key (a downgrade): his pin says his keys changed.
    answer.members[1] = { ...answer.members[1], ...(acct("bob").account.legacyIdentity() as PublicIdentity) };
    const rows = answer.members.map((m) => ({ ...m, role: m.role, email: m.email }));
    expect(() => planChange({ vaultId: VID(), answer, rows, keyEpoch: 0, what: "x", nameOf: () => null })).toThrow(KeyChangedError);
  });
});

describe("emergency access personal vaults", () => {
  it("counts a vault as shared when a trusted roster lists anyone else or it was seen signed", async () => {
    const r1 = signRoster("alice", null, 0, [["alice", "owner"], ["bob", "write"]]);
    h.server.rosters.set(VID(), [r1]);
    await as("alice");
    expect(sharedEvidence(VID())).toBe(false);
    await verifySnapshot([{ id: VID(), role: "owner", wrapped_key: v.vault.wrappedKey, key_kind: "account", key_epoch: 0, member_roster: r1, member_roster_seq: 1, share: null }], []);
    expect(sharedEvidence(VID())).toBe(true);
  });
});

describe("final review fixes (web)", () => {
  const unsignedRow = (vaultId = VID()): SignedVaultRow => {
    const key = vaultId === VID() ? vaultKey() : acct("alice").account.newVaultKey(vaultId).takeKey();
    const row: SignedVaultRow = { id: vaultId, role: "write", wrapped_key: key.shareTo(vaultId, pub("bob").public_key), key_kind: "sealed", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null };
    key.free();
    return row;
  };
  const ownRow = (): SignedVaultRow => ({ id: VID(), role: "owner", wrapped_key: v.vault.wrappedKey, key_kind: "account", key_epoch: 0, member_roster: null, member_roster_seq: 0, share: null });
  const unlockUnproven = (name: string) => {
    endSigning();
    const a = acct(name);
    h.server.user = a.id;
    return prepareSigning(a.account, { id: a.id, identity: null, key_pins_seq: 0 }, async () => ({ identity: null }), false);
  };

  it("M-A: config unknown on a server without the feature: a 404 on the identity turns the checks off, and nothing sticky is written", async () => {
    h.server.identity.set(id("alice"), null);
    h.server.fail = { path: "/account/identity", error: new h.ApiError(404, "not_found", "no route") };
    expect(await unlockUnproven("alice")).toBe(false);
    // Only the hash generated before the upload is remembered: nothing that keeps the checks on.
    expect(local.get(pinsKey(scope("alice")))).toBeUndefined();
    expect(readMemory(store, scope("alice"))).toMatchObject({ on: false, own: null });
    expect(checksRemembered(acct("alice").account, { user: { identity: null, key_pins_seq: 0 }, vaults: [ownRow()], invitations: [] })).toBe(false);
  });

  it("M-A: config unknown and the identity can't be uploaded (5xx): the checks run, but no memory 'on', local pins or server pins are written", async () => {
    h.server.identity.set(id("alice"), null);
    h.server.fail = { path: "/account/identity", error: new h.ApiError(503, "unavailable", "down") };
    expect(await unlockUnproven("alice")).toBe(true);
    expect(await verdict(ownRow())).toMatchObject({ status: "ok", trust: { kind: "own" } });
    await flushPins();
    expect(h.server.calls.some((c) => c.startsWith("PUT /account/key-pins"))).toBe(false);
    expect(local.get(pinsKey(scope("alice")))).toBeUndefined();
    expect(readMemory(store, scope("alice")).on).toBe(false);
    expect(checksRemembered(acct("alice").account, { user: { identity: null, key_pins_seq: 0 }, vaults: [ownRow()], invitations: [] })).toBe(false);
    // Then the server shows it signs (the upload works): from now on the checks stay on and the pins are kept.
    expect(await unlockUnproven("alice")).toBe(true);
    expect(signingReady()).toBe(true);
    expect(readMemory(store, scope("alice")).on).toBe(true);
    await verdict(ownRow());
    expect(local.get(pinsKey(scope("alice")))).toBeTruthy();
  });

  it("M-B: a device with no earlier record grandfathers nothing, even when this unlock made the identity: consent, unsigned accept allowed", async () => {
    h.server.identity.set(id("bob"), null);
    await as("bob", { identity: null });
    const c = await verdict(unsignedRow());
    expect(c).toMatchObject({ status: "consent", consent: { signer: null, unsignedAllowed: true } });
    expect(pinsNotice()).toBe(NEW_DEVICE);
    acceptConsent((c as { consent: Consent }).consent);
    expect(await verdict(unsignedRow())).toMatchObject({ status: "ok", trust: { kind: "unsigned" } });
    expect(pinsNotice()).toBeNull();
  });

  it("M-B: only vaults recorded here in an earlier unlock are grandfathered, not ones first seen in this one", async () => {
    h.server.identity.set(id("bob"), null);
    noteVaultsSeen(acct("bob").account, ["some-other-vault"]);
    endSigning();
    // This unlock's own record doesn't count as earlier.
    await as("bob", { identity: null });
    noteVaultsSeen(acct("bob").account, [VID()]);
    expect(await verdict(unsignedRow())).toMatchObject({ status: "consent", consent: { unsignedAllowed: false } });
    expect(JSON.parse(local.get(seenKey(scope("bob")))!)).toEqual(["some-other-vault", VID()]);
  });

  it("L-A: a lost answer to the identity upload still counts as made here when the listed record opens to the hash generated here", async () => {
    h.server.identity.set(id("bob"), null);
    noteVaultsSeen(acct("bob").account, [VID()]);
    h.server.lose = "/account/identity";
    await as("bob", { identity: null });
    expect(signingReady()).toBe(false);
    // Next unlock: the server lists the record it stored; it opens to the hash this device generated.
    await as("bob");
    expect(signingReady()).toBe(true);
    expect(await verdict(unsignedRow())).toMatchObject({ status: "ok", trust: { kind: "unsigned" } });
    expect(pinsNotice()).toBeNull();
  });

  it("L-A: on identity_exists nothing is grandfathered in that sync (no empty list written)", async () => {
    noteVaultsSeen(acct("bob").account, [VID()]);
    // The server lists none, but already has one (another device made it): 409 identity_exists.
    await as("bob", { identity: null });
    expect(signingReady()).toBe(true);
    expect((await verdict(unsignedRow())).status).toBe("consent");
    await flushPins();
    const stored = h.server.pins.get(id("bob"));
    const pins = stored?.key_pins ? acct("bob").account.openKeyPins(stored.key_pins, stored.seq) : null;
    expect(pins?.grandfathered ?? null).toBeNull();
    expect(pinsNotice()).toBeNull();
  });

  it("L-B: accepting is bound to the consent the dialog showed (signer, key id, epoch, roster)", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    const c = ((await verdict(row)) as { consent: Consent }).consent;
    expect(() => acceptConsent(c, { ...c, epoch: { ...c.epoch, key_id: "another-key" } })).toThrow(CHANGED_SINCE_SHOWN);
    expect(() => acceptConsent(c, { ...c, signer: { ...c.signer!, hash: "another" } })).toThrow(CHANGED_SINCE_SHOWN);
    expect(() => acceptConsent(c, { ...c, roster: null })).toThrow(CHANGED_SINCE_SHOWN);
    expect(personState(pub("alice")).status).toBe("new");
    acceptConsent(c, { ...c });
    expect(await verdict(row)).toMatchObject({ status: "ok" });
  });

  it("L-B: accepting an invitation is bound to the trust its dialog showed", async () => {
    const row = sharedRow("bob", "write");
    await as("bob");
    const inv = (await verifySnapshot([], [invitationOf(row)]))!.invitations.get(row.id)!;
    expect(inv.kind).toBe("signed");
    if (inv.kind !== "signed") return;
    expect(() => acceptInvitationTrust(row.id, inv, { ...inv, epoch: { ...inv.epoch, key_epoch: 9 } })).toThrow(CHANGED_SINCE_SHOWN);
    expect(() => acceptInvitationTrust(row.id, inv, { kind: "unsigned" })).toThrow(CHANGED_SINCE_SHOWN);
    acceptInvitationTrust(row.id, inv, inv);
    expect(await verdict(row)).toMatchObject({ status: "ok" });
  });

  it("pins the email the trust dialog showed, not the one pinned before", async () => {
    await as("bob");
    trustPerson(pub("alice"), "alice@example.com", { mode: "trust", shownHash: core.verifyIdentity(pub("alice")).hash });
    trustPerson(pub("alice"), "Alice@Example.com", { mode: "verify", shownHash: core.verifyIdentity(pub("alice")).hash });
    expect(personState(pub("alice")).pinnedEmail).toBe("alice@example.com");
  });

  it("tombstones an accepted shared vault a verified sync no longer lists; it isn't used if served again", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    expect(await verdict(row)).toMatchObject({ status: "ok" });
    await verifySnapshot([], []);
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: VAULT_LEFT });
  });

  it("records a tombstone while sharing is paused", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    await verdict(row);
    await flushPins();
    await as("bob", { identity: acct("carol").record });
    expect(signingProblem()).toBe(SHARING_PAUSED);
    markLeft(VID(), 1);
    await as("bob");
    expect(await verdict(row)).toMatchObject({ status: "refused", reason: VAULT_LEFT });
  });

  it("merges another tab's unsent change at the same version instead of dropping it", async () => {
    const row = sharedRow("bob", "write");
    await bobAccepts(row);
    await verdict(row);
    await flushPins();
    const saved = JSON.parse(local.get(pinsKey(scope("bob")))!) as { seq: number; sealed: string };
    // Another tab declines a vault (a tombstone) at the same version and hasn't sent it yet.
    const theirs = acct("bob").account.openKeyPins(saved.sealed, saved.seq);
    const withLeft = core.pinsLeave(theirs, "vault-other-tab", 1, 100);
    local.set(pinsKey(scope("bob")), JSON.stringify({ seq: saved.seq, sealed: acct("bob").account.sealKeyPins({ ...withLeft, version: saved.seq }, saved.seq), dirty: true }));
    // This tab changes the pins too.
    trustPerson(pub("alice"), "alice@example.com", { mode: "verify", shownHash: core.verifyIdentity(pub("alice")).hash });
    const now = JSON.parse(local.get(pinsKey(scope("bob")))!) as { seq: number; sealed: string; dirty: boolean };
    const merged = acct("bob").account.openKeyPins(now.sealed, now.seq);
    expect(now.dirty).toBe(true);
    expect(merged.left?.["vault-other-tab"]).toBeTruthy();
    expect(merged.pins.find((p) => p.user_id === id("alice"))?.verified).toBe(true);
    await flushPins();
    const server = h.server.pins.get(id("bob"))!;
    expect(acct("bob").account.openKeyPins(server.key_pins!, server.seq).left?.["vault-other-tab"]).toBeTruthy();
  });

  it("never writes the local key pins over a stored copy it can't read", async () => {
    const row = sharedRow("bob", "write");
    local.set(pinsKey(scope("bob")), "{broken");
    await bobAccepts(row);
    expect(local.get(pinsKey(scope("bob")))).toBe("{broken");
  });

  it("after a version-1 review pins and signs the emails the review showed, not a later members answer's", async () => {
    await as("alice");
    await verifySnapshot([ownRow()], []);
    const answer = (email: string): MembersAnswer => ({
      members: [
        { ...pub("alice"), email: EMAIL.alice, name: "alice", role: "owner", key_kind: "account", share: null },
        { ...pub("bob"), email, name: "bob", role: "write", key_kind: "sealed", share: null },
      ] as MembersAnswer["members"],
      keyEpoch: 0,
      roster: null,
      rosterSeq: 0,
    });
    const rows = (email: string) => [
      { ...pub("alice"), role: "owner", email: EMAIL.alice },
      { ...pub("bob"), role: "write", email },
    ];
    const input = (email: string) => ({ vaultId: VID(), answer: answer(email), rows: rows(email), keyEpoch: 0, what: "didn't change the key", nameOf: () => null });
    let review: ReviewNeededError | null = null;
    try {
      planChange(input("bob@example.com"));
    } catch (e) {
      review = e as ReviewNeededError;
    }
    const shown = review!.review.members.find((m) => m.userId === id("bob"))!;
    expect(shown.email).toBe("bob@example.com");
    // The confirmed call sees a members answer that lists Bob with another email: the shown one is pinned and signed.
    const p = planChange({ ...input("mallory@example.com"), confirmed: { digest: review!.review.digest, missing: [], emails: { [id("bob")]: shown.email } } });
    expect(p.rows.find((r) => r.user_id === id("bob"))!.email).toBe("bob@example.com");
    pinReviewed(p);
    expect(personState(pub("bob")).pinnedEmail).toBe("bob@example.com");
  });
});
