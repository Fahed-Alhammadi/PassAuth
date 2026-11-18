/**
 * Signed sharing through `vault.ts` against a fake server (real core): sharing sends a signed share and roster, an
 * invitee sees it signed and only signed invitations can be accepted, key replacement signs every share and sends
 * every item's revision (and tries again after a concurrent edit), `members_changed` names who differs, people who
 * left need a confirmation, vaults from before are labelled and can be re-signed, a vault whose check fails is never
 * opened, and servers without `signed_sharing` get the requests from before.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/passauth_core";
import { ROLLBACK_KEPT, ROLLBACK_SHOWN } from "./item-revs";
import { loadCore, signedVectors, unb64, vectorAccounts, type SignedVectors } from "./test-core";

type Opts = { method?: string; body?: unknown };
const h = vi.hoisted(() => ({
  handler: null as null | ((path: string, opts: Opts) => Promise<unknown>),
  config: { features: [] as string[] } as { features: string[] } | null,
}));

vi.mock("./api", async (importOriginal) => {
  const orig = await importOriginal<typeof import("./api")>();
  return {
    ...orig,
    api: (path: string, opts?: Opts) => h.handler!(path, opts ?? {}),
    getTokens: () => ({ access: "access", refresh: "refresh" }),
    setTokens: () => {},
    knownPublicConfig: () => h.config,
    loadPublicConfig: async () => h.config,
    refreshPublicConfig: async () => h.config,
  };
});

class FakeSocket {
  onopen: unknown = null;
  onmessage: unknown = null;
  onclose: unknown = null;
  close() {}
}
const storage = new Map<string, string>();
vi.stubGlobal("WebSocket", FakeSocket);
vi.stubGlobal("location", new URL("https://vault.example.test/"));
vi.stubGlobal("localStorage", {
  getItem: (k: string) => storage.get(k) ?? null,
  setItem: (k: string, v: string) => void storage.set(k, v),
  removeItem: (k: string) => void storage.delete(k),
});

import { ApiError, SERVER_UPDATE_NEEDED, serverTooOld } from "./api";
import { emptyItem } from "./types";
import {
  ReviewNeededError,
  acceptConsent,
  acceptInvitation,
  declineConsent,
  declineInvitation,
  getBundle,
  rotateVaultKeys,
  boot,
  getState,
  lock,
  login,
  logout,
  register,
  removeMember,
  requireCurrentServer,
  resignVault,
  restoreUnlocked,
  rotateVaultKey,
  shareVault,
  sync as syncNow,
  updateItem,
} from "./vault";

let v: SignedVectors;
let accounts: ReturnType<typeof vectorAccounts>;
const EMAIL: Record<string, string> = { alice: "alice@example.com", bob: "bob@example.com", carol: "carol@example.com" };

beforeAll(async () => {
  await loadCore();
  v = await signedVectors();
  accounts = vectorAccounts(v);
  // The vectors carry session bytes, not bundles: the fake server's bundle is `{account_id}`, and "this account's own
  // bundle" is modelled by its account id (the core's real check is tested in the core). `bundleRefused` makes it fail.
  vi.spyOn(core.Account.prototype, "matchesBundle").mockImplementation(function (this: core.Account, b: unknown) {
    const id = (b as { account_id?: unknown } | null)?.account_id;
    return !bundleRefused && id === (this.legacyIdentity() as { user_id: string }).user_id;
  });
});
let bundleRefused = false;
afterAll(() => vi.unstubAllGlobals());

// ------------------------------------------------------------- fake server

interface Member {
  role: string;
  wrapped_key: string;
  key_kind: "account" | "sealed";
  status: "active" | "invited";
  share: { signature: string; signer: Record<string, unknown>; signer_deleted: boolean } | null;
}
interface ItemRow {
  id: string;
  vault_id: string;
  item_key: string;
  data: string;
  revision: number;
  deleted_at: null;
  created_at: number;
  updated_at: number;
}
interface World {
  me: string;
  revision: number;
  identity: Map<string, core.IdentityRecord | null>;
  pins: Map<string, { key_pins: string | null; seq: number }>;
  vault: { id: string; meta: string; epoch: number; rosters: string[]; members: Map<string, Member>; items: Map<string, ItemRow> };
  calls: { method: string; path: string; body: unknown }[];
  /** Answers for the next matching request (an error, thrown once). */
  next: { path: string; error: Error; before?: () => void }[];
  /** A server from before signed sharing: no identity or key pins routes (404). */
  noSigning?: boolean;
  /** A server from before key epochs: vault rows carry none. */
  noEpoch?: boolean;
  /** The server leaves the vault out of `/sync` but still answers its members list (a server omitting it on purpose). */
  omitOnly?: boolean;
  /** `/sync` `user.account_wraps_v2` (undefined: left out, a server from before). */
  wrapsV2?: unknown;
}
let w: World;

const id = (name: string) => accounts.get(name)!.id;
const nameOf = (userId: string) => [...accounts].find(([, a]) => a.id === userId)![0];
const pub = (name: string) => v.identities.find((i) => i.name === name)!.publicIdentity;
const userRow = (userId: string) => {
  const n = nameOf(userId);
  const rec = w.identity.get(userId);
  return {
    user_id: userId,
    email: EMAIL[n],
    name: n[0].toUpperCase() + n.slice(1),
    public_key: pub(n).public_key,
    signing_key: rec ? rec.signing_key : null,
    identity_signature: rec ? rec.identity_signature : null,
    x25519_signature: rec ? rec.x25519_signature : null,
  };
};
const identityOf = (userId: string) => {
  const r = userRow(userId);
  return { user_id: r.user_id, public_key: r.public_key, signing_key: r.signing_key, identity_signature: r.identity_signature, x25519_signature: r.x25519_signature };
};
const rosterLatest = () => w.vault.rosters[w.vault.rosters.length - 1] ?? null;

function vaultRow(userId: string) {
  const m = w.vault.members.get(userId)!;
  return {
    id: w.vault.id,
    meta: w.vault.meta,
    role: m.role,
    wrapped_key: m.wrapped_key,
    key_kind: m.key_kind,
    rotation_pending: 0,
    ...(w.noEpoch ? {} : { key_epoch: w.vault.epoch }),
    seq: 1,
    member_roster: rosterLatest(),
    member_roster_seq: w.vault.rosters.length,
    share: m.share,
  };
}

/** The account id the fake server's /sync answers for (null: the caller's). */
let syncAs: string | null = null;

function sync() {
  const me = w.me;
  const m = w.vault.members.get(me);
  const active = m?.status === "active" && !w.omitOnly;
  const rec = w.identity.get(me);
  return {
    revision: w.revision,
    user: {
      id: syncAs ?? me,
      email: EMAIL[nameOf(me)],
      name: nameOf(me),
      email_verified: true,
      identity: rec ?? null,
      key_pins_seq: w.pins.get(me)?.seq ?? 0,
      ...(w.wrapsV2 !== undefined ? { account_wraps_v2: w.wrapsV2 } : {}),
    },
    bundle: { account_id: me },
    vaults: active ? [vaultRow(me)] : [],
    items: active ? [...w.vault.items.values()] : [],
    invitations:
      m?.status === "invited"
        ? [
            {
              vault_id: w.vault.id,
              role: m.role,
              wrapped_key: m.wrapped_key,
              meta: w.vault.meta,
              invited_by: { id: id("alice"), ...userRow(id("alice")) },
              invited_at: 1,
              key_epoch: w.vault.epoch,
              share: m.share,
              member_roster: rosterLatest(),
              member_roster_seq: w.vault.rosters.length,
            },
          ]
        : [],
  };
}

const err = (status: number, code: string, fields: Record<string, unknown> = {}) => new ApiError(status, code, code, undefined, undefined, { error: code, ...fields });

/** The server's own checks of a roster after a change: the next version, listing exactly the members. */
function storeRoster(roster: string | undefined, epoch: number) {
  if (roster === undefined) {
    if (w.vault.rosters.length) throw err(400, "update_required");
    return;
  }
  const r = JSON.parse(roster) as { version: number; key_epoch: number };
  if (r.version !== w.vault.rosters.length + 1) throw err(409, "member_roster_changed");
  const diff = core.compareMembers(
    roster,
    [...w.vault.members].map(([u, m]) => ({ ...identityOf(u), role: m.role })),
  );
  if (r.key_epoch !== epoch || diff.unknown.length || diff.identity_changed.length || diff.role_changed.length || diff.missing.length)
    throw err(409, "members_changed", { ...diff, key_epoch: epoch });
  w.vault.rosters.push(roster);
}

const snapshot = () => ({ ...userRow(w.me) });

async function handle(path: string, opts: Opts): Promise<unknown> {
  const method = opts.method ?? (opts.body === undefined ? "GET" : "POST");
  w.calls.push({ method, path, body: opts.body });
  const i = w.next.findIndex((n) => path.startsWith(n.path));
  if (i >= 0) {
    const [n] = w.next.splice(i, 1);
    n.before?.();
    throw n.error;
  }
  const vid = w.vault.id;
  const b = (opts.body ?? {}) as Record<string, unknown>;
  if (path === "/sync") return sync();
  if (path === "/sync/revision") return { revision: w.revision };
  if (path === "/account") return {};
  if (w.noSigning && path.startsWith("/account/")) throw new ApiError(404, "not_found", `no route ${method} ${path}`);
  if (path === "/account/identity") {
    const have = w.identity.get(w.me);
    if (have && JSON.stringify(have) !== JSON.stringify(b)) throw err(409, "identity_exists");
    w.identity.set(w.me, b as unknown as core.IdentityRecord);
    w.revision++;
    return { ok: true, created: true };
  }
  if (path === "/account/key-pins") {
    const have = w.pins.get(w.me) ?? { key_pins: null, seq: 0 };
    if (method === "GET") return have;
    if (b.seq !== have.seq + 1) throw err(409, "key_pins_changed");
    w.pins.set(w.me, { key_pins: b.key_pins as string, seq: b.seq as number });
    w.revision++;
    return { seq: b.seq };
  }
  if (path.startsWith(`/vaults/${vid}/rosters?after=`)) {
    const after = Number(path.split("=")[1]);
    return { rosters: w.vault.rosters.slice(after), latest: w.vault.rosters.length, more: false };
  }
  if (path === `/vaults/${vid}/members` && method === "GET") {
    // Like the real server: only members and invitees see the list.
    if (!w.vault.members.has(w.me)) throw err(404, "not_found");
    return {
      members: [...w.vault.members].map(([u, m]) => ({ ...userRow(u), role: m.role, status: m.status, key_kind: m.key_kind, share: m.share })),
      key_epoch: w.vault.epoch,
      member_roster: rosterLatest(),
      member_roster_seq: w.vault.rosters.length,
    };
  }
  if (path === `/vaults/${vid}/members` && method === "POST") {
    if (b.key_epoch !== undefined && b.key_epoch !== w.vault.epoch) throw err(409, "vault_key_changed");
    const to = b.user_id as string;
    const prev = w.vault.members.get(to);
    const share = typeof b.signature === "string" ? { signature: b.signature, signer: snapshot(), signer_deleted: false } : null;
    if (share) core.verifyShare(vid, identityOf(to), b.role as string, w.vault.epoch, b.sealed_key as string, identityOf(w.me), share.signature);
    w.vault.members.set(to, { role: b.role as string, wrapped_key: b.sealed_key as string, key_kind: "sealed", status: prev?.status ?? "invited", share });
    try {
      storeRoster(b.roster as string | undefined, w.vault.epoch);
    } catch (e) {
      if (prev) w.vault.members.set(to, prev);
      else w.vault.members.delete(to);
      throw e;
    }
    w.revision++;
    return { revision: w.revision, status: prev?.status ?? "invited" };
  }
  const remove = new RegExp(`^/vaults/${vid}/members/([^/]+)/remove$`).exec(path);
  if (path === `/vaults/${vid}/rotate` || remove) {
    if (b.key_epoch !== w.vault.epoch) throw err(409, "vault_key_changed");
    const before = new Map(w.vault.members);
    if (remove) w.vault.members.delete(remove[1]);
    const keys = b.keys as { user_id: string; wrapped_key: string; key_kind: "account" | "sealed"; signature?: string }[];
    const items = b.items as { id: string; key: string; data: string; revision?: number }[];
    for (const it of items) {
      const have = w.vault.items.get(it.id)!;
      if (it.revision !== undefined && it.revision !== have.revision) {
        w.vault.members = before;
        throw err(409, "revision_conflict");
      }
    }
    try {
      storeRoster(b.roster as string | undefined, w.vault.epoch + 1);
    } catch (e) {
      w.vault.members = before;
      throw e;
    }
    for (const k of keys) {
      const m = w.vault.members.get(k.user_id)!;
      if (k.signature) core.verifyShare(vid, identityOf(k.user_id), m.role, w.vault.epoch + 1, k.wrapped_key, identityOf(w.me), k.signature);
      w.vault.members.set(k.user_id, { ...m, wrapped_key: k.wrapped_key, key_kind: k.key_kind, share: k.signature ? { signature: k.signature, signer: snapshot(), signer_deleted: false } : null });
    }
    for (const it of items) w.vault.items.set(it.id, { ...w.vault.items.get(it.id)!, item_key: it.key, data: it.data, revision: w.vault.items.get(it.id)!.revision + 1 });
    if (typeof b.meta === "string") w.vault.meta = b.meta;
    w.vault.epoch++;
    w.revision++;
    return { revision: w.revision, key_epoch: w.vault.epoch, vault_seq: 2, member_roster_seq: w.vault.rosters.length };
  }
  if (path === `/vaults/${vid}/resign`) {
    if (b.key_epoch !== w.vault.epoch) throw err(409, "vault_key_changed");
    const keys = b.keys as { user_id: string; wrapped_key: string; signature: string }[];
    for (const k of keys) {
      const m = w.vault.members.get(k.user_id)!;
      core.verifyShare(vid, identityOf(k.user_id), m.role, w.vault.epoch, k.wrapped_key, identityOf(w.me), k.signature);
      w.vault.members.set(k.user_id, { ...m, wrapped_key: k.wrapped_key, share: { signature: k.signature, signer: snapshot(), signer_deleted: false } });
    }
    storeRoster(b.roster as string, w.vault.epoch);
    w.revision++;
    return { revision: w.revision, member_roster_seq: w.vault.rosters.length };
  }
  if (path === `/vaults/${vid}/invitation/accept`) {
    w.vault.members.get(w.me)!.status = "active";
    w.revision++;
    return { revision: w.revision, status: "active" };
  }
  const put = /^\/items\/([^/]+)$/.exec(path);
  if (put && method === "PUT") {
    const have = w.vault.items.get(put[1])!;
    if (b.revision !== have.revision) throw err(409, "revision_conflict");
    w.vault.items.set(put[1], { ...have, item_key: b.key as string, data: b.data as string, revision: have.revision + 1 });
    w.revision++;
    return { revision: have.revision + 1 };
  }
  throw new ApiError(404, "not_found", `no route ${method} ${path}`);
}

// ----------------------------------------------------------------- set-up

function newWorld(features: string[]) {
  h.config = { features };
  h.handler = handle;
  storage.clear();
  const alice = accounts.get("alice")!.account;
  const key = alice.openVaultKey(v.vault.id, v.vault.wrappedKey, "account", 0, true);
  const item = key.encryptItem({ ...emptyItem("login"), name: "Mail", created_at: 1, updated_at: 1 }, "item-1", v.vault.id) as { key: string; data: string };
  const meta = key.encryptMeta(v.vault.id, { name: "Team" });
  key.free();
  w = {
    me: id("alice"),
    revision: 1,
    identity: new Map(v.accounts.map((a) => [a.id, a.record])),
    pins: new Map(),
    vault: {
      id: v.vault.id,
      meta,
      epoch: 0,
      rosters: [],
      members: new Map([[id("alice"), { role: "owner", wrapped_key: v.vault.wrappedKey, key_kind: "account", status: "active", share: null } as Member]]),
      items: new Map([["item-1", { id: "item-1", vault_id: v.vault.id, item_key: item.key, data: item.data, revision: 1, deleted_at: null, created_at: 1, updated_at: 1 }]]),
    },
    calls: [],
    next: [],
  };
}

async function signIn(name: string) {
  lock();
  w.me = id(name);
  const a = v.accounts.find((x) => x.name === name)!;
  await boot();
  await restoreUnlocked(a.id, unb64(a.sessionBytes));
}

const found = (name: string) => ({ ...identityOf(id(name)), name, email: EMAIL[name] });
const lastCall = (pred: (c: World["calls"][number]) => boolean) => [...w.calls].reverse().find(pred);

/** Alice shares with someone the old way (an app from before signed sharing): no signature, no roster. */
function legacyShare(name: string, role: string, status: "active" | "invited" = "active") {
  const key = accounts.get("alice")!.account.openVaultKey(v.vault.id, v.vault.wrappedKey, "account", 0, true);
  w.vault.members.set(id(name), { role, wrapped_key: key.shareTo(v.vault.id, pub(name).public_key), key_kind: "sealed", status, share: null });
  key.free();
}

beforeEach(() => {
  syncAs = null;
  newWorld(["vault_invitations", "signed_sharing"]);
});

/** Run a change; when it asks for the member review, check it and confirm exactly what it showed. */
async function confirming<T>(run: (c?: { digest: string; missing: string[] }) => Promise<T>, check?: (r: ReviewNeededError["review"]) => void): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (!(e instanceof ReviewNeededError)) throw e;
    check?.(e.review);
    return run({ digest: e.review.digest, missing: e.review.missing.map((m) => m.userId) });
  }
}

const vid = () => v.vault.id;
/** The invitation's trust as its Accept dialog captured it. */
const shownInvitation = () => getState().invitations.find((i) => i.vaultId === vid())?.trust;

describe("signed sharing in the vault", () => {
  it("shares a vault for the first time only after the version-1 review; the invitee sees it signed and accepts it", async () => {
    await signIn("alice");
    expect(getState().vaults[0].trust).toEqual({ kind: "own" });
    // The first signed list needs the review (H4): nothing is sent before the user confirms it.
    await expect(shareVault(vid(), found("bob"), "write")).rejects.toBeInstanceOf(ReviewNeededError);
    expect(w.calls.some((c) => c.method === "POST" && c.path.endsWith("/members"))).toBe(false);
    const status = await confirming(
      (c) => shareVault(vid(), found("bob"), "write", { confirmed: c }),
      (r) => {
        expect(r.first).toBe(true);
        expect(r.members.map((m) => m.label)).toEqual(expect.arrayContaining(["You", "bob@example.com"]));
      },
    );
    expect(status).toBe("invited");
    const post = lastCall((c) => c.method === "POST" && c.path.endsWith("/members"))!.body as Record<string, unknown>;
    expect(post).toMatchObject({ user_id: id("bob"), role: "write", key_epoch: 0, signature: expect.any(String), roster: expect.any(String) });
    expect(w.vault.rosters).toHaveLength(1);

    await signIn("bob");
    const inv = getState().invitations[0];
    expect(inv.trust).toMatchObject({ kind: "signed", signer: { label: "alice@example.com", pin: "new" } });
    await acceptInvitation(vid(), shownInvitation());
    const s = getState();
    expect(s.vaults).toHaveLength(1);
    expect(s.vaults[0]).toMatchObject({ name: "Team", trust: { kind: "signed", signer: { label: "alice@example.com" } }, rosterSeq: 1 });
    expect(s.items.map((i) => i.item.name)).toEqual(["Mail"]);
    expect(s.blockedVaults).toEqual([]);
    expect(s.consents).toEqual([]);
  });

  it("a second share needs no review (the trusted roster lists everyone else)", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    expect(await shareVault(vid(), found("carol"), "read")).toBe("invited");
    expect(w.vault.rosters).toHaveLength(2);
  });

  it("holds a vault the server planted as an active membership for consent, and never uses it before (H2/H3)", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    // The server makes Bob a member without him accepting anything.
    w.vault.members.get(id("bob"))!.status = "active";
    await signIn("bob");
    let s = getState();
    expect(s.vaults).toEqual([]);
    expect(s.items).toEqual([]);
    expect(s.consents).toMatchObject([{ id: vid(), name: "Team", consent: { signer: { label: "alice@example.com" } } }]);
    await acceptConsent(vid(), getState().consents[0].consent);
    s = getState();
    expect(s.consents).toEqual([]);
    expect(s.vaults[0]).toMatchObject({ name: "Team", trust: { kind: "signed" } });
  });

  it("declining a planted vault leaves it for good", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.vault.members.get(id("bob"))!.status = "active";
    await signIn("bob");
    await declineConsent(vid());
    expect(w.calls.some((c) => c.method === "DELETE" && c.path === `/vaults/${vid()}/members/${id("bob")}`)).toBe(true);
  });

  it("refuses to accept an unsigned invitation on a server that signs", async () => {
    legacyShare("bob", "write", "invited");
    await signIn("bob");
    expect(getState().invitations[0].trust).toEqual({ kind: "unsigned" });
    await expect(acceptInvitation(vid(), shownInvitation())).rejects.toThrow(/isn't signed/);
    expect(w.calls.some((c) => c.path.endsWith("/invitation/accept"))).toBe(false);
  });

  it("refuses a forged invitation (sealed and signed by someone the roster doesn't make an owner or admin)", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("carol"), "read", { confirmed: c }));
    // Carol (read access) forges an invitation for Bob.
    const key = accounts.get("alice")!.account.openVaultKey(vid(), v.vault.wrappedKey, "account", 0, true);
    const carol = accounts.get("carol")!.account.openSigningIdentity(accounts.get("carol")!.record);
    const forged = carol.sealAndSignShare(key, vid(), pub("bob"), "write", 0);
    key.free();
    w.vault.members.set(id("bob"), { role: "write", wrapped_key: forged.sealed_key, key_kind: "sealed", status: "invited", share: { signature: forged.signature, signer: userRow(id("carol")), signer_deleted: false } });
    await signIn("bob");
    expect(getState().invitations[0].trust).toMatchObject({ kind: "refused" });
    await expect(acceptInvitation(vid(), shownInvitation())).rejects.toThrow();
  });

  it("labels a grandfathered share from before 'not yet signed', and the owner re-signs it after the review", async () => {
    legacyShare("bob", "write");
    w.identity.set(id("bob"), null);
    // An earlier session on Bob's device, with an app from before signed sharing: the vault was here then (this app
    // refuses a server that doesn't sign, so that session's memory is written as that app left it).
    storage.set(`pa.vault-seen.https://vault.example.test|${id("bob")}`, JSON.stringify([vid()]));
    // Bob's first signed sync: this unlock makes his identity, and the vault from before stays usable.
    await signIn("bob");
    expect(getState().vaults[0].trust).toEqual({ kind: "unsigned" });

    await signIn("alice");
    await expect(resignVault(vid())).rejects.toBeInstanceOf(ReviewNeededError);
    await confirming((c) => resignVault(vid(), { confirmed: c }), (r) => expect(r.first).toBe(true));
    const body = lastCall((c) => c.path.endsWith("/resign"))!.body as { keys: unknown[]; roster: string; key_epoch: number };
    expect(body.keys).toHaveLength(1);
    expect(body.key_epoch).toBe(0);
    expect(w.vault.rosters).toHaveLength(1);

    // Round 5: signed for the first time at the key Bob already holds: his OK once (Accept or Not now, no Decline).
    await signIn("bob");
    expect(getState().vaults).toHaveLength(0);
    const c = getState().consents[0];
    expect(c.consent).toMatchObject({ firstSigned: true, declinable: false, signer: { label: "alice@example.com" } });
    await expect(declineConsent(vid())).rejects.toThrow("can't be declined here");
    await acceptConsent(vid(), c.consent);
    expect(getState().vaults[0].trust).toMatchObject({ kind: "signed", signer: { label: "alice@example.com" } });
  });

  it("replaces the key of a vault without a roster only after the version-1 review (C1)", async () => {
    legacyShare("bob", "write");
    await signIn("alice");
    await expect(rotateVaultKey(vid())).rejects.toBeInstanceOf(ReviewNeededError);
    expect(w.calls.some((c) => c.path.endsWith("/rotate"))).toBe(false);
    // Automatic flows never create version 1.
    await expect(rotateVaultKeys([vid()])).rejects.toThrow(/didn't replace its key automatically/);
    await confirming((c) => rotateVaultKey(vid(), { confirmed: c }));
    const body = lastCall((c) => c.path.endsWith("/rotate"))!.body as { keys: { key_kind: string; signature?: string }[]; roster: string };
    expect(body.roster).toBeTruthy();
    expect(body.keys.find((k) => k.key_kind === "sealed")?.signature).toBeTruthy();
  });

  it("re-keys a personal vault without a roster for its owner alone, nothing signed", async () => {
    await signIn("alice");
    await rotateVaultKeys([vid()], new Map([[vid(), [id("alice")]]]));
    const body = lastCall((c) => c.path.endsWith("/rotate"))!.body as { keys: { key_kind: string }[]; roster?: string; items: { revision?: number }[] };
    expect(body.roster).toBeUndefined();
    expect(body.keys).toEqual([expect.objectContaining({ user_id: id("alice"), key_kind: "account" })]);
    // Signed mode: every item still carries its revision, so an edit made meanwhile isn't overwritten.
    expect(body.items[0].revision).toBe(1);
  });

  it("an automatic key replacement stops when the members differ from the set that was checked", async () => {
    await signIn("alice");
    legacyShare("bob", "write");
    await expect(rotateVaultKeys([vid()], new Map([[vid(), [id("alice")]]]))).rejects.toThrow(/members changed/);
    expect(w.calls.some((c) => c.path.endsWith("/rotate"))).toBe(false);
  });

  it("replaces the key with signed shares and every item's revision, trying again after a concurrent edit", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.next.push({
      path: `/vaults/${vid()}/rotate`,
      error: err(409, "revision_conflict"),
      before: () => {
        const it = w.vault.items.get("item-1")!;
        w.vault.items.set("item-1", { ...it, revision: it.revision + 1 });
        w.revision++;
      },
    });
    await rotateVaultKey(vid());
    const sent = w.calls.filter((c) => c.path.endsWith("/rotate"));
    expect(sent).toHaveLength(2);
    const [first, second] = sent.map((c) => c.body as { items: { revision: number }[]; keys: { key_kind: string; signature?: string }[]; roster: string });
    expect(first.items[0].revision).toBe(1);
    expect(second.items[0].revision).toBe(2);
    expect(second.keys.find((k) => k.key_kind === "sealed")?.signature).toBeTruthy();
    expect(w.vault.epoch).toBe(1);
    expect(w.vault.rosters).toHaveLength(2);
    expect(getState().vaults[0].epoch).toBe(1);
  });

  it("stops a key replacement when the server lists someone the signed roster doesn't, and names them", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.vault.members.set(id("carol"), { role: "read", wrapped_key: "x", key_kind: "sealed", status: "active", share: null });
    await expect(rotateVaultKey(vid())).rejects.toThrow(/carol@example\.com.*didn't change the key/);
    expect(w.calls.some((c) => c.path.endsWith("/rotate"))).toBe(false);
  });

  it("shows who differs when the server answers members_changed, by name", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.next.push({
      path: `/vaults/${vid()}/rotate`,
      error: err(409, "members_changed", { unknown: [id("carol")], identity_changed: [], role_changed: [], missing: [] }),
      before: () => w.vault.members.set(id("carol"), { role: "read", wrapped_key: "x", key_kind: "sealed", status: "active", share: null }),
    });
    await expect(rotateVaultKey(vid())).rejects.toThrow(/carol@example\.com/);
  });

  it("asks per person before going on without someone who left, then removes a member with a signed key replacement", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await shareVault(vid(), found("carol"), "read");
    // Carol declines without a new key (allowed unsigned): the roster still lists her.
    w.vault.members.delete(id("carol"));
    let review: ReviewNeededError["review"] | null = null;
    await expect(
      removeMember(vid(), id("bob")).catch((e) => {
        review = (e as ReviewNeededError).review;
        throw e;
      }),
    ).rejects.toBeInstanceOf(ReviewNeededError);
    // Carol is named by her pinned email; Bob, being removed, isn't asked about.
    expect(review!.missing).toEqual([{ userId: id("carol"), role: "read", label: "carol@example.com" }]);
    // A confirmation without Carol's id doesn't do.
    await expect(removeMember(vid(), id("bob"), { confirmed: { digest: review!.digest, missing: [] } })).rejects.toBeInstanceOf(ReviewNeededError);
    await removeMember(vid(), id("bob"), { confirmed: { digest: review!.digest, missing: [id("carol")] } });
    expect(w.calls.some((c) => c.path.endsWith(`/members/${id("bob")}/remove`))).toBe(true);
    expect([...w.vault.members.keys()]).toEqual([id("alice")]);
    expect(w.vault.epoch).toBe(1);
  });

  it("never opens a vault whose share doesn't match its row, and shows why", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await signIn("bob");
    await acceptInvitation(vid(), shownInvitation());
    // The server swaps Bob's role to admin (not what was signed).
    w.vault.members.get(id("bob"))!.role = "admin";
    await signIn("bob");
    const s = getState();
    expect(s.vaults).toEqual([]);
    expect(s.items).toEqual([]);
    expect(s.blockedVaults).toMatchObject([{ id: vid(), reason: expect.stringMatching(/couldn't verify/) }]);
  });

  it("refuses a sync answered for another account (H1)", async () => {
    await signIn("alice");
    syncAs = id("bob");
    await expect(syncNow()).rejects.toThrow(/another account/);
  });

  it("an edit after signing still saves (revision checks unchanged)", async () => {
    await signIn("alice");
    const entry = getState().items[0];
    await updateItem(entry, { ...entry.item, name: "Mail 2" });
    expect(getState().items[0].item.name).toBe("Mail 2");
  });
});

describe("final review fixes (web)", () => {
  it("accepting an invitation needs exactly the trust its dialog showed (L-B)", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await signIn("bob");
    const shown = shownInvitation();
    expect(shown?.kind).toBe("signed");
    await expect(acceptInvitation(vid())).rejects.toThrow(/changed since PassAuth showed it/);
    if (shown?.kind === "signed") await expect(acceptInvitation(vid(), { ...shown, epoch: { ...shown.epoch, key_id: "other" } })).rejects.toThrow(/changed since/);
    expect(w.calls.some((c) => c.path.endsWith("/invitation/accept"))).toBe(false);
    await acceptInvitation(vid(), shown);
    expect(getState().vaults).toHaveLength(1);
  });

  it("accepting a vault needing consent needs exactly what its dialog showed (L-B)", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.vault.members.get(id("bob"))!.status = "active";
    await signIn("bob");
    const shown = getState().consents[0].consent;
    await expect(acceptConsent(vid(), { ...shown, rosterVersion: 7 })).rejects.toThrow(/changed since/);
    expect(getState().vaults).toEqual([]);
    await acceptConsent(vid(), shown);
    expect(getState().vaults).toHaveLength(1);
  });

  it("tombstones an accepted shared vault that disappears from a verified sync: served again, it isn't used", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await signIn("bob");
    await acceptInvitation(vid(), shownInvitation());
    const bob = w.vault.members.get(id("bob"))!;
    w.vault.members.delete(id("bob"));
    w.revision++;
    await syncNow();
    expect(getState().vaults).toEqual([]);
    // The server puts the old membership back.
    w.vault.members.set(id("bob"), bob);
    w.revision++;
    await syncNow();
    expect(getState().vaults).toEqual([]);
    expect(getState().blockedVaults).toMatchObject([{ id: vid(), reason: expect.stringMatching(/left or declined/) }]);
  });

  it("rule 3: a vault one sync omits isn't tombstoned while the server still lists its members; two omitted syncs in a row are", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await signIn("bob");
    await acceptInvitation(vid(), shownInvitation());
    w.omitOnly = true;
    w.revision++;
    await syncNow();
    expect(getState().vaults).toEqual([]);
    // Listed again: still the accepted vault (no tombstone after one omission).
    w.omitOnly = false;
    w.revision++;
    await syncNow();
    expect(getState().vaults).toHaveLength(1);
    // Omitted twice in a row: confirmed, tombstoned.
    w.omitOnly = true;
    w.revision++;
    await syncNow();
    w.revision++;
    await syncNow();
    w.omitOnly = false;
    w.revision++;
    await syncNow();
    expect(getState().vaults).toEqual([]);
    expect(getState().blockedVaults).toMatchObject([{ id: vid(), reason: expect.stringMatching(/left or declined/) }]);
  });

  it("rule 1: an unsigned vault waiting for consent is never declined; one that can't be accepted unsigned stays locked", async () => {
    legacyShare("bob", "write");
    await signIn("bob");
    // Trust memory missing (an identity from before, no key pins): accept allowed, decline not.
    const c = getState().consents[0];
    expect(c.consent).toMatchObject({ signer: null, unsignedAllowed: true });
    await expect(declineConsent(vid())).rejects.toThrow(/Ask the vault's owner to sign this vault/);
    expect(w.calls.some((x) => x.method === "DELETE")).toBe(false);
  });

  it("a key replacement over the server's limit (429 rate_limited) says so and changes nothing", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    w.next.push({ path: `/vaults/${vid()}/rotate`, error: err(429, "rate_limited") });
    await expect(rotateVaultKey(vid())).rejects.toThrow(/replaced many times in the last hour/);
    expect(w.vault.epoch).toBe(0);
  });

  it("a fresh device whose identity the server claims this unlock created grandfathers nothing (M-B)", async () => {
    legacyShare("bob", "write");
    w.identity.set(id("bob"), null);
    await signIn("bob");
    const s = getState();
    expect(s.vaults).toEqual([]);
    expect(s.consents).toMatchObject([{ id: vid(), consent: { signer: null, unsignedAllowed: true } }]);
    expect(s.signingNotice).toMatch(/no earlier copy/);
    await acceptConsent(vid(), s.consents[0].consent);
    expect(getState().vaults[0].trust).toEqual({ kind: "unsigned" });
  });
});

describe("sticky checks (H2)", () => {
  it("keep running when the server's features can't be read", async () => {
    h.config = null;
    await signIn("alice");
    expect(w.calls.some((c) => c.path === "/account/key-pins" || c.path === "/account/identity")).toBe(true);
    expect(getState().vaults[0].trust).toEqual({ kind: "own" });
  });

  it("keep running once the account has signed state here, while the server's features can't be read", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    h.config = null;
    await signIn("alice");
    expect(getState().vaults[0].trust).toEqual({ kind: "own" });
    // Still signed: an unsigned share would be refused by the server and isn't sent.
    await shareVault(vid(), found("carol"), "read");
    const post = lastCall((c) => c.method === "POST" && c.path.endsWith("/members"))!.body as Record<string, unknown>;
    expect(post.signature).toBeTruthy();
  });
});

describe("servers without signed sharing are refused", () => {
  beforeEach(() => {
    newWorld(["vault_invitations"]);
    for (const k of [...w.identity.keys()]) w.identity.set(k, null);
  });

  it("a server that doesn't list the feature is asked for no vault: start-up says so and unlocking fails with the message", async () => {
    lock();
    await logout();
    w.calls = [];
    await boot();
    expect(getState().status).toBe("unreachable");
    expect(getState().serverOutdated).toBe(true);
    const a = v.accounts.find((x) => x.name === "alice")!;
    await expect(restoreUnlocked(a.id, unb64(a.sessionBytes))).rejects.toThrow();
    expect(getState().vaults).toEqual([]);
    expect(w.calls.some((c) => c.path.startsWith("/sync"))).toBe(false);
  });

  it("the server stops listing the feature while this app holds the account's bundle: the sync is refused, nothing is asked for or used", async () => {
    h.config = { features: ["vault_invitations", "signed_sharing"] };
    w.identity = new Map(v.accounts.map((x) => [x.id, x.record]));
    await signIn("alice");
    expect(getState().vaults).toHaveLength(1);
    h.config = { features: ["vault_invitations"] };
    w.calls = [];
    await expect(signIn("alice")).rejects.toThrow(SERVER_UPDATE_NEEDED);
    expect(getState().serverOutdated).toBe(true);
    expect(getState().vaults).toEqual([]);
    expect(getState().items).toEqual([]);
    expect(w.calls).toEqual([]);
    // Unlocked again once the server is updated.
    h.config = { features: ["vault_invitations", "signed_sharing"] };
    await signIn("alice");
    // An open vault whose server stops listing the feature: it stays as shown, nothing more is written or synced.
    h.config = { features: ["vault_invitations"] };
    w.calls = [];
    await expect(updateItem(getState().items[0], { ...getState().items[0].item, name: "Changed" })).rejects.toThrow(SERVER_UPDATE_NEEDED);
    await expect(rotateVaultKey(vid())).rejects.toThrow(SERVER_UPDATE_NEEDED);
    await expect(shareVault(vid(), found("bob"), "read")).rejects.toThrow(SERVER_UPDATE_NEEDED);
    await expect(syncNow()).rejects.toThrow(SERVER_UPDATE_NEEDED);
    expect(w.calls).toEqual([]);
    expect(getState().serverOutdated).toBe(true);
    expect(getState().items.map((i) => i.item.name)).toEqual(["Mail"]);
    h.config = { features: ["vault_invitations", "signed_sharing"] };
    await signIn("alice");
    expect(getState().serverOutdated).toBe(false);
    expect(getState().vaults).toHaveLength(1);
  });

  it("features unknown and the server answers that it doesn't sign (404 on the identity): refused, nothing used or made sticky", async () => {
    w.noSigning = true;
    legacyShare("bob", "write");
    h.config = null;
    await expect(signIn("bob")).rejects.toThrow(SERVER_UPDATE_NEEDED);
    const s = getState();
    expect(s.vaults).toEqual([]);
    expect(s.items).toEqual([]);
    expect(s.consents).toEqual([]);
    expect([...storage.keys()].some((k) => k.startsWith("pa.key-pins."))).toBe(false);
    expect([...storage.entries()].some(([k, val]) => k.startsWith("pa.vault-trust.") && JSON.parse(val).on === true)).toBe(false);
    // Nothing is written to such a server either.
    await expect(shareVault(vid(), found("carol"), "read")).rejects.toThrow();
    expect(w.calls.some((c) => c.method === "POST" && c.path.endsWith("/members"))).toBe(false);
  });

  it("features unknown and vault rows without a key epoch (a server from before signing): the checks still run, nothing opens unchecked", async () => {
    w.noEpoch = true;
    w.noSigning = true;
    h.config = null;
    await expect(signIn("alice")).rejects.toThrow(SERVER_UPDATE_NEEDED);
    expect(getState().vaults).toEqual([]);
    expect(getState().items).toEqual([]);
  });

  it("signing in and creating an account are refused before anything is sent", async () => {
    w.calls = [];
    await expect(login("alice@example.com", "pw", null)).rejects.toThrow(SERVER_UPDATE_NEEDED);
    await expect(register("new@example.com", "New", "pw", false)).rejects.toThrow(SERVER_UPDATE_NEEDED);
    await expect(requireCurrentServer()).rejects.toThrow(SERVER_UPDATE_NEEDED);
    expect(w.calls).toEqual([]);
    // A config that can't be fetched decides nothing.
    h.config = null;
    await expect(requireCurrentServer()).resolves.toBeUndefined();
    expect(serverTooOld(null)).toBe(false);
    expect(serverTooOld({ api: 2, features: [] } as never)).toBe(true);
    expect(serverTooOld({} as never)).toBe(true);
    expect(serverTooOld({ api: 2, features: ["signed_sharing"] } as never)).toBe(false);
  });
});

describe("round 5 (web)", () => {
  /** This device's saved key pins for `name` (opened). */
  const savedPins = (name: string) => {
    const key = [...storage.keys()].find((k) => k.startsWith("pa.key-pins.") && k.endsWith(id(name)));
    if (!key) return null;
    const l = JSON.parse(storage.get(key)!) as { seq: number; sealed: string };
    return accounts.get(name)!.account.openKeyPins(l.sealed, l.seq);
  };

  it("a saved session is used only with this account's own bundle (matchesBundle)", async () => {
    w.me = id("alice");
    await boot();
    bundleRefused = true;
    try {
      const a = v.accounts.find((x) => x.name === "alice")!;
      await expect(restoreUnlocked(a.id, unb64(a.sessionBytes))).rejects.toThrow("master password");
      expect(getState().status).not.toBe("unlocked");
    } finally {
      bundleRefused = false;
    }
  });

  it("a sync's bundle is kept only when it is the unlocked account's own", async () => {
    await signIn("alice");
    const before = getBundle();
    const orig = h.handler!;
    h.handler = async (path, opts) => {
      const r = await orig(path, opts);
      return path.startsWith("/sync") ? { ...(r as object), bundle: { account_id: id("bob") } } : r;
    };
    try {
      await syncNow();
    } finally {
      h.handler = orig;
    }
    expect(getBundle()).toBe(before);
  });

  it("I2: a declined invitation is tombstoned only after the server answered", async () => {
    await signIn("alice");
    await confirming((c) => shareVault(vid(), found("bob"), "write", { confirmed: c }));
    await signIn("bob");
    expect(getState().invitations[0].trust).toMatchObject({ kind: "signed", declinable: true });
    w.next.push({ path: `/vaults/${vid()}/invitation`, error: err(500, "server_error") });
    await expect(declineInvitation(vid())).rejects.toBeTruthy();
    expect(savedPins("bob")?.left?.[vid()]).toBeUndefined();
    // Answered (404 here: already gone counts): tombstoned at roster version 0, never the server's chain version.
    await declineInvitation(vid());
    expect(savedPins("bob")?.left?.[vid()]?.roster_version).toBe(0);
  });

  it("M2: an unsigned invitation's decline tombstones nothing (it can never be accepted)", async () => {
    legacyShare("bob", "write", "invited");
    await signIn("bob");
    await declineInvitation(vid());
    expect(savedPins("bob")?.left?.[vid()]).toBeUndefined();
  });
});

describe("security round 7/9 (web)", () => {
  const savedPins = (name: string) => {
    const key = [...storage.keys()].find((k) => k.startsWith("pa.key-pins.") && k.endsWith(id(name)));
    if (!key) return null;
    const l = JSON.parse(storage.get(key)!) as { seq: number; sealed: string };
    return accounts.get(name)!.account.openKeyPins(l.sealed, l.seq);
  };
  const ownWrap = () => {
    const body = lastCall((c) => c.path.endsWith("/rotate"))!.body as { keys: { user_id: string; wrapped_key: string }[] };
    return body.keys.find((k) => k.user_id === id("alice"))!.wrapped_key;
  };
  const rekeyAlone = () => rotateVaultKeys([vid()], new Map([[vid(), [id("alice")]]]));

  it("7: re-keys an own vault with an epoch-bound wrap only when the sync says every app reads it, then refuses a v1 wrap at that epoch", async () => {
    w.wrapsV2 = true;
    await signIn("alice");
    await rekeyAlone();
    const wrapped = ownWrap();
    expect(core.accountWrapIsBound(wrapped)).toBe(true);
    expect(w.vault.epoch).toBe(1);
    // Opened from the v2 wrap: recorded in the key pins (bound_since), so a v1 wrap at or below epoch 1 is refused.
    expect(getState().vaults.map((x) => x.id)).toEqual([vid()]);
    expect(savedPins("alice")?.epochs?.[vid()]?.bound_since).toBe(1);
    // The server serves a v1 wrap of the same key at the same epoch: never opened.
    const alice = accounts.get("alice")!.account;
    const key = alice.openVaultKey(vid(), wrapped, "account", 1, false);
    const legacy = key.wrapFor(alice, vid());
    key.free();
    expect(core.accountWrapIsBound(legacy)).toBe(false);
    w.vault.members.set(id("alice"), { ...w.vault.members.get(id("alice"))!, wrapped_key: legacy });
    w.revision++;
    await syncNow();
    expect(getState().vaults).toHaveLength(0);
    expect(getState().blockedVaults.map((b) => b.id)).toEqual([vid()]);
  });

  it("7: writes v1 wraps when the hint is missing, not true, or false", async () => {
    for (const hint of [undefined, "true", 1, false]) {
      newWorld(["vault_invitations", "signed_sharing"]);
      w.wrapsV2 = hint;
      await signIn("alice");
      await rekeyAlone();
      expect(core.accountWrapIsBound(ownWrap()), String(hint)).toBe(false);
      // Still opens (legacy allowed: nothing bound yet).
      expect(getState().vaults.map((x) => x.id)).toEqual([vid()]);
      expect(savedPins("alice")?.epochs?.[vid()]?.bound_since ?? null).toBeNull();
    }
  });

  const serve = (row: { item_key: string; data: string }) => {
    w.vault.items.set("item-1", { ...w.vault.items.get("item-1")!, item_key: row.item_key, data: row.data, revision: w.vault.items.get("item-1")!.revision + 1 });
    w.revision++;
  };
  const shown = () => getState().items.find((e) => e.id === "item-1")!;
  const remembered = () => {
    const key = [...storage.keys()].find((k) => k.startsWith("pa.item-revs.") && k.endsWith(id("alice")));
    return key ? (JSON.parse(storage.get(key)!) as Record<string, number>) : null;
  };

  it("9: an older version served after a newer one keeps the newer copy shown and warns; after a reload it shows the served one, warned", async () => {
    await signIn("alice");
    expect(shown().item.rev).toBe(1);
    expect(remembered()).toEqual({ "item-1": 1 });
    const old = { ...w.vault.items.get("item-1")! };
    await updateItem(shown(), { ...shown().item, name: "Mail 2" });
    expect(shown().item).toMatchObject({ name: "Mail 2", rev: 2 });
    expect(remembered()).toEqual({ "item-1": 2 });
    // The server serves the first version again.
    serve(old);
    await syncNow();
    expect(shown()).toMatchObject({ rollback: true, item: { name: "Mail 2", rev: 2 } });
    expect(getState().warnings).toContain(ROLLBACK_KEPT);
    expect(remembered()).toEqual({ "item-1": 2 });
    // A new page (nothing newer in memory): the served copy, warned.
    await signIn("alice");
    expect(shown()).toMatchObject({ rollback: true, item: { name: "Mail", rev: 1 } });
    expect(getState().warnings).toContain(ROLLBACK_SHOWN);
    expect(getState().warnings).not.toContain(ROLLBACK_KEPT);
    expect(remembered()).toEqual({ "item-1": 2 });
  });

  it("9: an edit of the warned copy saves over the server's older one with a higher counter", async () => {
    await signIn("alice");
    const old = { ...w.vault.items.get("item-1")! };
    await updateItem(shown(), { ...shown().item, name: "Mail 2" });
    serve(old);
    await syncNow();
    await updateItem(shown(), { ...shown().item, name: "Mail 3" });
    expect(shown().rollback).toBeUndefined();
    expect(shown().item).toMatchObject({ name: "Mail 3", rev: 3 });
    expect(getState().warnings).not.toContain(ROLLBACK_KEPT);
  });

  it("9: the same counter with other content is accepted (an edit by an app from before the counter)", async () => {
    await signIn("alice");
    const key = accounts.get("alice")!.account.openVaultKey(vid(), v.vault.wrappedKey, "account", 0, true);
    // An app that drops `rev` writes 0 + 1 = 1 again.
    const other = key.encryptItem({ ...emptyItem("login"), name: "Other", created_at: 1, updated_at: 2, rev: 0 }, "item-1", vid()) as { key: string; data: string };
    key.free();
    serve({ item_key: other.key, data: other.data });
    await syncNow();
    expect(shown().item.name).toBe("Other");
    expect(shown().rollback).toBeUndefined();
    expect(getState().warnings.some((x) => x.startsWith("Your server sent older"))).toBe(false);
  });

  it("9: forgets the counters of items the server no longer has", async () => {
    await signIn("alice");
    expect(remembered()).toEqual({ "item-1": 1 });
    w.vault.items.delete("item-1");
    w.revision++;
    await syncNow();
    expect(remembered()).toEqual({});
  });

  it("9: a key replacement counts the counter up and isn't taken for a change by someone else", async () => {
    await signIn("alice");
    await rekeyAlone();
    expect(shown().item.rev).toBe(2);
    expect(shown().rollback).toBeUndefined();
    expect(remembered()).toEqual({ "item-1": 2 });
  });
});
