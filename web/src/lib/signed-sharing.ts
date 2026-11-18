/**
 * Signed sharing, the app side (docs/ARCHITECTURE.md "Signed sharing", steps 0–8).
 *
 * While the vault is unlocked this module holds the account's signing identity (created and uploaded at the first
 * unlock, opened at every later one, checked against the one the key pins remember) and its key pins (other people's
 * identities, the vaults the account accepted with their keys, tombstones), sealed with the account key and kept on the
 * server by compare-and-swap, with this device's newest copy kept locally. "Me" is always the account the core
 * unlocked, never the server's `user.id`, and this device's trust memory is per server and account.
 *
 * Every sync checks every vault row and invitation with the core before `vault.ts` uses it: the member roster chain
 * (within caps), the key's commitment to it, the share signature with its signer's pinned identity, and the vault's
 * admission (`pinsAdmit`: the key epoch and key id against the pins, tombstones, consent for vaults never accepted).
 * Pins and roster memory are written only after every check of a row passed. A vault that fails is never opened.
 *
 * Sharing, key replacement and re-signing are planned here (`planChange`: the member review the user confirms, by its
 * digest, whenever the vault has no trusted roster yet or people are missing) and signed with a vault key `vault.ts`
 * passes in (never held across an await). Nothing here trusts the server. Pure helpers live in `signing.ts`.
 */
import * as core from "../wasm/passauth_core";
import { api, hasErrorCode } from "./api";
import { server } from "./server";
import {
  ACCOUNT_MISMATCH,
  ASK_OWNER_TO_SIGN,
  AUTOMATIC_NEEDS_REVIEW,
  MEMORY_UNREADABLE,
  STILL_CHECKING,
  NEW_DEVICE,
  MALFORMED,
  NOT_YET_SIGNED,
  PINS_ROLLED_BACK,
  PINS_UNREADABLE,
  ROSTER_BYTES_MAX,
  ROSTER_PAGES_MAX,
  ROSTER_VERSIONS_MAX,
  SHARING_PAUSED,
  TOO_MANY_CHANGES,
  TRUST_MEMORY_MISSING,
  VAULT_REFUSED,
  VAULT_UNOPENABLE,
  cleanText,
  emailConflictText,
  identityOf,
  keysChangedText,
  listedAs,
  membersDifferText,
  readIdentityRecord,
  addSeen,
  localPinsState,
  memoryUnreadable,
  readLocalPins,
  readMemory,
  readSeen,
  readRosterText,
  readRostersPage,
  readShare,
  refusedText,
  rosterMember,
  rosterNumbers,
  rosterUserIds,
  trustScope,
  updateMemory,
  writeLocalPins,
  type DeviceMemory,
  type KeyValueStore,
  type MembersAnswer,
  type NameOf,
  type PublicIdentity,
  type ShareSigner,
  type SignedMemberRow,
  type VaultMemory,
} from "./signing";

export type KeyPins = core.KeyPins;

/** A share's signer as the app shows them: the pinned email first, the server's only as "listed by your server as …". */
export interface SignerView {
  identity: PublicIdentity;
  /** What to call them: the pinned email, else the email (or name) the server kept with the share. */
  label: string;
  /**
   * The email shown for them in `normalizeEmail` form: the pinned one, else the one the server kept with the share ("" when
   * there is none). Accepting pins exactly this (rule 4); it is part of what an Accept is bound to.
   */
  email: string;
  listedAs: string | null;
  fingerprint: string;
  hash: string;
  pin: string;
  verified: boolean;
  deleted: boolean;
}

/** How much a usable vault's key is vouched for. */
export type VaultTrust =
  /** The account's own wrap (a personal vault, or one it owns). */
  | { kind: "own" }
  /** The share is signed by `signer` (an owner or admin of the vault's trusted member roster). */
  | { kind: "signed"; signer: SignerView | null }
  /** A share from before signed sharing, present at the account's first signed sync: usable, labelled "Not yet signed". */
  | { kind: "unsigned" };

/** Someone whose keys changed since this account pinned them (or a new account using a pinned email): what needed them stopped. */
export interface KeyChange {
  identity: PublicIdentity;
  /** What to call them (the pinned email, else the listed one). */
  email: string;
  /** The new identity's fingerprint and hash, to compare with them before trusting it. */
  fingerprint: string;
  hash: string;
  status: "changed" | "email_conflict";
}

/** A sealed vault the account never accepted (planted, or accepted on an app whose pins were lost): shown like an invitation. */
export interface Consent {
  vaultId: string;
  role: string;
  /** The account left or declined it before; it was shared again with a newer member list. */
  rejoin: boolean;
  /**
   * A vault already accepted, never seen signed, with a new key (unsigned, or signed for the first time: a "puppet
   * signer" can only reach the user this way): accept only if expected.
   */
  replaced: boolean;
  /** The account held this vault with its own key wrap: a personal vault now comes as one someone else sealed. */
  own: boolean;
  /** Signed for the first time at the key the account already holds: its first signer is trusted only with the user's OK. */
  firstSigned: boolean;
  /** `pinsAdmit`'s `declinable`: Decline may be offered (`pinsDecline`); otherwise only "Not now" (it stays locked). */
  declinable: boolean;
  /**
   * The account's trust memory is missing for this vault (no key pins on the server, or no earlier copy on this device
   * at the first signed sync): an unsigned vault may be accepted too ("Not yet signed", by the key id shown), and it
   * isn't offered for decline (a server can't push the user into leaving real vaults).
   */
  unsignedAllowed: boolean;
  /** The verified signer; null when the share isn't signed (never offered for decline: rule 1). */
  signer: SignerView | null;
  roster: string | null;
  rosterVersion: number | null;
  /** `rosterHash` per version of the roster chain fetched for this check (null: none fetched), sent with the accept. */
  chainHashes: Record<string, string> | null;
  epoch: core.EpochPin;
}

export type VaultVerdict =
  | { status: "ok"; trust: VaultTrust; rosterSeq: number }
  | { status: "consent"; consent: Consent }
  | { status: "refused"; reason: string; changed?: KeyChange };

/** How an invitation is vouched for. */
export type InvitationTrust =
  /** Signed: the signer's identity checked against the pins, the roster chain, roles and the key's commitment. */
  | {
      kind: "signed";
      signer: SignerView;
      roster: string;
      rosterVersion: number;
      chainHashes: Record<string, string> | null;
      epoch: core.EpochPin;
      /** Admission flags (shown, and bound to the accept): a re-join, a newer key for a vault the account holds (`held`), … */
      rejoin: boolean;
      replaced: boolean;
      own: boolean;
      firstSigned: boolean;
      held: boolean;
      /** Decline may be offered; otherwise only "Not now" (a puppet-signed invitation must not lead to giving a vault up). */
      declinable: boolean;
    }
  /** Not signed, on a server that signs: decline only. */
  | { kind: "unsigned" }
  /** Signed, but a check failed: decline only. */
  | { kind: "refused"; reason: string; changed?: KeyChange };

export interface Verdicts {
  vaults: Map<string, VaultVerdict>;
  invitations: Map<string, InvitationTrust>;
}

/** A sync row as far as signed sharing reads it (extra fields from `/sync`). */
export interface SignedVaultRow {
  id: string;
  role: string;
  wrapped_key: string;
  key_kind: string;
  key_epoch?: unknown;
  member_roster?: unknown;
  member_roster_seq?: unknown;
  share?: unknown;
}

export interface SignedInvitationRow {
  vault_id: string;
  role: string;
  wrapped_key: string;
  key_epoch?: unknown;
  share?: unknown;
  member_roster?: unknown;
}

// ------------------------------------------------------------------ session

interface Session {
  account: core.Account;
  /** The account the core unlocked (never the server's `user.id`). */
  accountId: string;
  /** Device memory key: server origin + account id. */
  scope: string;
  identity: core.SigningIdentity | null;
  /** The identity others' statements name for this account: the signing identity's, or the legacy one before it exists. */
  me: PublicIdentity;
  /** Set when the server's identity record isn't this account's: nothing is signed and every sealed vault is refused. */
  paused: string | null;
  /** This unlock made the account's signing identity (its first signed sync: unsigned shares are grandfathered). */
  createdIdentity: boolean;
  /**
   * The server showed it signs (config lists `signed_sharing`, an identity `PUT`/`GET` or `GET /account/key-pins`
   * succeeded, or a share, roster or identity was seen). Until then the checks run but nothing that keeps them on for
   * good (memory `on`, local pins, server pins) is written (review M-A).
   */
  proven: boolean;
  /** `PUT /account/identity` answered 404 before the server showed it signs: this server doesn't sign (this sync). */
  notSigning: boolean;
  /** The identity hash this session generated before `PUT /account/identity` (review L-A). */
  generated: string | null;
  /** `identity_exists` in this sync: the identity state is settled at the next one, so nothing is grandfathered now. */
  skipGrandfather: boolean;
  /** Vaults waiting without trust memory (device memory `missing`): may be accepted unsigned, never offered for decline. */
  missing: Set<string>;
  missingWhy: "pins" | "device";
  /**
   * Shared (sealed) vaults that passed a check in this session: tombstoned when later verified syncs no longer list them,
   * once confirmed (rule 3).
   */
  sharedSeen: Set<string>;
  /** Per accepted shared vault, how many consecutive verified syncs didn't list it (a tombstone needs two, or a 404). */
  absent: Map<string, number>;
  /**
   * This device's trust memory is stored but can't be read (rule 7): shared vaults are refused, own vaults keep their
   * epoch and key id checks against the server's pins (read only), and nothing is written.
   */
  broken: boolean;
  /**
   * The server's key pins and this device's remember different own identities (`identity_mismatch` from a merge): sharing
   * is paused and nothing is merged or written (neither on this device nor to the server) for the session.
   */
  frozen: boolean;
  /** The vault row ids of the last sync checked (a decline never tombstones one of them: `pinsDecline` `currentRow`). */
  rows: Set<string>;
  /** The local copy this session wrote last (to tell another tab's write). */
  lastWritten: string | null;
  pins: KeyPins | null;
  /** The server's version these pins are based on. */
  pinsSeq: number;
  loaded: boolean;
  /** Local changes not on the server yet. */
  dirty: boolean;
  /** The server's copy looked rolled back or unreadable: this device's copy is used and not written over the server's. */
  held: boolean;
  notice: string | null;
  /** "Your list of known keys is missing" / "no earlier copy here", while such vaults wait. */
  missingNotice: string | null;
  /** Bumped whenever the pinned people change (cached verdicts depend on them). */
  peopleVersion: number;
  peopleJson: string;
  cache: Map<string, { key: string; verdict: VaultVerdict | InvitationTrust; roster?: string | null; epoch?: number }>;
  flushing: Promise<void> | null;
  /** Per vault that passed this sync's checks: the roster it trusts (null: none) and the verified key epoch. */
  verified: Map<string, { roster: string | null; epoch: number }>;
}

let session: Session | null = null;

/**
 * The vault ids this device recorded for an account before this unlock (per scope; null: none recorded, a new device),
 * read once per unlock before this unlock records its own (review M-B).
 */
let earlier: { scope: string; ids: string[] | null } | null = null;

const storage: KeyValueStore = {
  get(key) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      if (value === null) localStorage.removeItem(key);
      else localStorage.setItem(key, value);
    } catch {
      /* storage unavailable: this device then can't tell a rolled-back roster or list */
    }
  },
};
let store: KeyValueStore = storage;

/** Tests: another device-local store. */
export function useStore(s: KeyValueStore) {
  store = s;
}

/** The device-local store in use (also for other per-account device memory, e.g. `item-revs.ts`). */
export const deviceStore = (): KeyValueStore => store;

const now = () => Math.floor(Date.now() / 1000);
const errCode = (e: unknown) => (e instanceof Error ? e.message : String(e));
const wholeNumber = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER;

/** This server's origin, for device memory keys (the desktop app talks to any server from one origin). */
function origin(): string {
  try {
    return server.origin();
  } catch {
    return server.base;
  }
}

/** The account the core unlocked. */
export const accountIdOf = (account: core.Account): string => (account.legacyIdentity() as PublicIdentity).user_id;

/** Device memory scope of an account on the current server. */
export const scopeOf = (account: core.Account) => trustScope(origin(), accountIdOf(account));

/** Free the signing identity and forget the session (the vault locked or signed out). */
export function endSigning() {
  session?.identity?.free();
  session = null;
  earlier = null;
}

/** The vaults recorded here for `scope` before this unlock (null: nothing recorded: a new device or account here). */
function earlierSeen(scope: string): string[] | null {
  if (earlier?.scope !== scope) earlier = { scope, ids: readSeen(store, scope) };
  return earlier.ids;
}

/**
 * Record the vaults this unlock uses (opened and shown, with or without signed sharing): at the account's first signed
 * sync on a later unlock only these are grandfathered.
 */
export function noteVaultsSeen(account: core.Account, ids: readonly string[]) {
  const scope = scopeOf(account);
  earlierSeen(scope);
  addSeen(store, scope, ids);
}

/** Whether signing is set up for this unlocked session. */
export const signingReady = (): boolean => !!session?.identity && !session.paused;
/** Why sharing is paused on this device (the server lists a signing key that isn't this account's), or null. */
export const signingProblem = (): string | null => session?.paused ?? null;
/** "Your server sent an older list of known keys", or null. */
export const pinsNotice = (): string | null => session?.notice ?? session?.missingNotice ?? null;
/** This account's identity fingerprint, worked out from its own key (never the server's); null before it has one. */
export function identityFingerprint(): string | null {
  try {
    return session && !session.paused ? (session.identity?.fingerprint() ?? null) : null;
  } catch {
    return null;
  }
}

/**
 * Whether this device has to check signed sharing for an account even if the server doesn't list the feature (now):
 * it remembers signed state for it, or the sync answer carries any identity, share, roster or key pins (sticky checks).
 */
export function checksRemembered(
  account: core.Account,
  snap: { user: { identity?: unknown; key_pins_seq?: unknown }; vaults: readonly SignedVaultRow[]; invitations: readonly SignedInvitationRow[] },
): boolean {
  const scope = scopeOf(account);
  const memory = readMemory(store, scope);
  if (memory.on || memory.own || localPinsState(store, scope) !== null) return true;
  // Something is stored that can't be read: it may have said "on".
  if (memoryUnreadable(store, scope)) return true;
  if (snap.user.identity !== null && snap.user.identity !== undefined) return true;
  if (typeof snap.user.key_pins_seq === "number" && snap.user.key_pins_seq > 0) return true;
  const signedRow = (r: { share?: unknown; member_roster?: unknown }) => (r.share !== null && r.share !== undefined) || (r.member_roster !== null && r.member_roster !== undefined);
  return snap.vaults.some(signedRow) || snap.invitations.some(signedRow);
}

/**
 * Step 0, at every sync while the checks are on: the account must be the one the core unlocked (else nothing is used),
 * the key pins are loaded (rollback rule), and the signing identity opened (or made and uploaded the first time; on 409
 * `identity_exists` the stored one is read with `refetchUser`) and checked against the one the pins and this device
 * remember: none or another listed → paused.
 *
 * `proven`: the server has shown it signs (its config lists `signed_sharing`, or the account has signed state here or
 * in this answer). Without it (config unknown) the checks run but nothing that keeps them on for good is written until
 * the server shows it (review M-A); a 404 on `PUT /account/identity` then means this server doesn't sign: false is
 * returned and the caller runs this sync without the checks.
 */
export async function prepareSigning(
  account: core.Account,
  user: { id: string; identity?: unknown; key_pins_seq?: unknown },
  refetchUser: () => Promise<unknown>,
  proven = true,
): Promise<boolean> {
  const accountId = accountIdOf(account);
  if (user.id !== accountId) throw new Error(ACCOUNT_MISMATCH);
  const scope = trustScope(origin(), accountId);
  let s = session;
  if (!s || s.accountId !== accountId || s.scope !== scope || s.account !== account) {
    session?.identity?.free();
    const memory = readMemory(store, scope);
    s = session = {
      account,
      accountId,
      scope,
      identity: null,
      me: identityOf(account.legacyIdentity() as PublicIdentity),
      paused: null,
      createdIdentity: false,
      proven: false,
      notSigning: false,
      generated: null,
      skipGrandfather: false,
      missing: new Set(memory.missing ?? []),
      missingWhy: memory.missingWhy ?? "pins",
      sharedSeen: new Set(),
      absent: new Map(),
      broken: false,
      frozen: false,
      rows: new Set(),
      lastWritten: null,
      pins: null,
      pinsSeq: 0,
      loaded: false,
      dirty: false,
      held: false,
      notice: null,
      missingNotice: null,
      peopleVersion: 0,
      peopleJson: "[]",
      cache: new Map(),
      flushing: null,
      verified: new Map(),
    };
  }
  // The vaults recorded before this unlock, read before this unlock records any.
  earlierSeen(scope);
  // Stays set for the session once found (rule 7).
  s.broken = s.broken || memoryUnreadable(store, scope) || localPinsState(store, scope) === "unreadable";
  s.skipGrandfather = false;
  s.notSigning = false;
  if (proven) markProven(s);
  await loadPins(s, user.key_pins_seq);
  if (session !== s) return true;
  await checkIdentity(s, user.identity, refetchUser);
  if (session !== s) return true;
  if (s.notSigning && !s.proven) {
    // This server doesn't sign: nothing of this session is kept. The identity hash and the grandfathering candidates
    // recorded before the upload are dropped too (review r5 L2): a stale `earlier` list would otherwise decide the
    // grandfathering when this server signs one day, and lock every vault added since.
    if (s.generated) updateMemory(store, s.scope, { clearPending: true });
    s.identity?.free();
    session = null;
    return false;
  }
  return true;
}

/** The server showed it signs: from now on the checks stay on for this account here, and pins are kept and written. */
function markProven(s: Session) {
  if (s.proven) return;
  s.proven = true;
  updateMemory(store, s.scope, { on: true });
  if (s.identity) rememberOwnMemory(s, s.identity.identityHash());
  saveLocal(s);
}

/** The own identity hash in device memory (only once the server showed it signs). */
function rememberOwnMemory(s: Session, hash: string) {
  if (s.proven && !readMemory(store, s.scope).own) updateMemory(store, s.scope, { own: hash });
}

/** Pause sharing on this device for this session: nothing is signed, every sealed vault is refused. */
function pause(s: Session) {
  if (s.paused) return;
  s.paused = SHARING_PAUSED;
  s.identity?.free();
  s.identity = null;
  s.me = identityOf(s.account.legacyIdentity() as PublicIdentity);
  s.cache.clear();
}

function adopt(s: Session, identity: core.SigningIdentity) {
  s.identity?.free();
  s.identity = identity;
  s.me = identityOf(identity.publicIdentity() as PublicIdentity);
  // Shares to this account are checked against the new identity from now on.
  s.cache.clear();
}

/** The own identity hash this device and the pins remember (they must agree: else paused). */
function rememberedOwn(s: Session): string | null {
  return s.pins?.own_identity ?? readMemory(store, s.scope).own;
}

/** Remember the account's own identity (pins and device memory); a different one there pauses sharing. */
function rememberOwn(s: Session, hash: string): boolean {
  const memory = readMemory(store, s.scope);
  if (memory.own && memory.own !== hash) return false;
  const status = core.pinsCheckOwnIdentity(s.pins, hash);
  if (status === "mismatch") return false;
  // Unreadable device memory: the pins are read only (rule 7).
  if (status === "new" && !s.broken) {
    try {
      setPins(s, core.pinsSetOwnIdentity(s.pins, hash) as KeyPins);
    } catch {
      return false;
    }
  }
  rememberOwnMemory(s, hash);
  return true;
}

async function checkIdentity(s: Session, record: unknown, refetchUser: () => Promise<unknown>) {
  if (s.paused) return;
  const rec = readIdentityRecord(record);
  if (rec === MALFORMED) return pause(s);
  if (rec === null) {
    // None listed, but this account had one: the server dropped it (a rollback). Never make a second one.
    if (s.identity || rememberedOwn(s)) return pause(s);
    // Unreadable device memory may be what remembered one (review r5 I4): never upload a second identity then.
    if (s.broken) return;
    return createIdentity(s, refetchUser);
  }
  if (s.identity) {
    const mine = s.identity.publicIdentity() as PublicIdentity;
    if (rec.signing_key === mine.signing_key && rec.identity_signature === mine.identity_signature && rec.x25519_signature === mine.x25519_signature) return;
    return pause(s);
  }
  openIdentity(s, rec);
}

function openIdentity(s: Session, rec: unknown) {
  const r = readIdentityRecord(rec);
  if (r === null || r === MALFORMED) return pause(s);
  let identity: core.SigningIdentity;
  try {
    identity = s.account.openSigningIdentity(r);
  } catch {
    // identity_mismatch (keys that aren't this account's) or decrypt_failed: never sign or verify with them.
    return pause(s);
  }
  const hash = identity.identityHash();
  // An own identity this device or the pins already knew before this open: then a hash generated here doesn't make
  // this the identity's first signed sync (rule 6).
  const knownBefore = !!rememberedOwn(s);
  const unwritten = s.pins?.grandfathered === null || s.pins?.grandfathered === undefined;
  if (!rememberOwn(s, hash)) {
    identity.free();
    return pause(s);
  }
  adopt(s, identity);
  // Made here, even if the answer to its `PUT` was lost: a server can't forge a record that opens under the account key
  // to a hash this device generated (review L-A).
  // Also when the unlock that created it (`created: true`) remembered it but its first signed sync slipped: the pins
  // still lack the grandfathered list (review r5 I1).
  if ((!knownBefore || unwritten) && (s.generated === hash || readMemory(store, s.scope).generated.includes(hash))) s.createdIdentity = true;
}

const statusOf = (e: unknown): number | null => {
  const st = (e as { status?: unknown } | null)?.status;
  return typeof st === "number" ? st : null;
};

async function createIdentity(s: Session, refetchUser: () => Promise<unknown>) {
  let made: core.NewSigningIdentity;
  try {
    made = s.account.newSigningIdentity();
  } catch {
    return;
  }
  let identity: core.SigningIdentity | null = null;
  try {
    identity = made.takeIdentity();
    const hash = identity.identityHash();
    // Remembered before the upload (session and device memory), so a lost answer can still be told apart (L-A), with
    // the vaults this device showed as usable before (recorded once, at the first generation: rule 6), so the first
    // signed sync grandfathers exactly those even when it slips to a later unlock.
    s.generated = hash;
    updateMemory(store, s.scope, { generated: hash, earlier: earlierSeen(s.scope) });
    let answer: { created?: unknown } | null;
    try {
      answer = await api<{ created?: unknown } | null>("/account/identity", { method: "PUT", body: made.record });
    } catch (e) {
      if (session !== s) return;
      if (hasErrorCode(e, "identity_exists")) {
        // Another device (or a request of this one whose answer was lost) made the account's identity: use the stored
        // one. Grandfathering waits for the next sync, when the identity state is known (rule 2).
        markProven(s);
        s.skipGrandfather = true;
        const user = await refetchUser().catch(() => null);
        if (session !== s) return;
        const stored = user && typeof user === "object" ? (user as { identity?: unknown }).identity : undefined;
        if (stored) openIdentity(s, stored);
        return;
      }
      // Not found before the server showed it signs: this server doesn't sign. Anything else: tried at the next sync.
      if (!s.proven && statusOf(e) === 404) s.notSigning = true;
      return;
    }
    if (session !== s) return;
    markProven(s);
    if (!rememberOwn(s, hash)) return pause(s);
    adopt(s, identity);
    identity = null;
    // Only an identity the server says this request created makes this the account's first signed sync.
    s.createdIdentity = answer?.created === true;
  } finally {
    identity?.free();
    made.free();
  }
}

/** Load the key pins: the server's copy (opened, version checked), merged with this device's unsent changes. */
async function loadPins(s: Session, serverSeq: unknown) {
  const seq = wholeNumber(serverSeq) ? serverSeq : 0;
  // Once loaded, a lower number is a sync answer from before this session's own write (or a rollback, which the next
  // write finds: `flushPins`); only a higher one is read.
  if (s.loaded && seq <= s.pinsSeq) return;
  const local = readLocalPins(store, s.scope);
  let localPins: KeyPins | null = null;
  if (local) {
    try {
      localPins = s.account.openKeyPins(local.sealed, local.seq);
    } catch {
      // Stored, but it can't be opened: this device's memory is unreadable (rule 7).
      localPins = null;
      s.broken = true;
    }
  }
  const localSeq = localPins && local ? local.seq : 0;
  const hold = (notice: string) => {
    if (localPins) {
      try {
        setPinsRaw(s, s.pins ? mergeCopies(localPins, !!local?.dirty, s.pins, s.dirty) : localPins);
      } catch (e) {
        if (!mismatched(s, e)) throw e;
      }
    }
    s.pinsSeq = Math.max(localSeq, s.pinsSeq);
    s.dirty = s.dirty || !!local?.dirty;
    s.held = true;
    s.notice = notice;
    s.loaded = true;
  };
  if (seq < localSeq) return hold(PINS_ROLLED_BACK);
  let serverPins: KeyPins | null = null;
  let got = seq;
  if (seq > 0) {
    const r = await api<{ key_pins?: unknown; seq?: unknown } | null>("/account/key-pins");
    if (session !== s) return;
    got = wholeNumber(r?.seq) ? r.seq : -1;
    if (got < localSeq) return hold(PINS_ROLLED_BACK);
    if (typeof r?.key_pins === "string" && r.key_pins) {
      try {
        serverPins = s.account.openKeyPins(r.key_pins, got);
      } catch (e) {
        return hold(errCode(e) === "rollback" ? PINS_ROLLED_BACK : PINS_UNREADABLE);
      }
    } else if (got > 0) return hold(PINS_UNREADABLE);
  }
  // This device's last-known pins (its local copy and this session's) are always merged into a newer server copy, not
  // only unsent changes (rule 5): retired keys, tombstones and rosters this device knows are never dropped because
  // another device wrote first. Unsent changes win (`mergePins`); a last-known copy only adds what never goes back
  // (`pinsMergeLastKnown`: the server's person pins win, so two devices never rewrite each other's in a loop, review r5
  // M1). When the merge adds anything, it is written back. Another own identity: paused, nothing merged or written.
  let pins = serverPins;
  let dirty = false;
  try {
    for (const [ours, unsent] of [
      [localPins, !!local?.dirty],
      [s.pins, s.dirty],
    ] as const) {
      if (!ours) continue;
      if (!pins) {
        // No server copy (version 0): this device's is the only one; unsent while it was.
        pins = ours;
        dirty = dirty || unsent;
        continue;
      }
      const merged = (unsent ? core.mergePins(pins, ours) : core.pinsMergeLastKnown(pins, ours)) as KeyPins;
      if (!samePins(merged, pins)) dirty = true;
      pins = merged;
    }
  } catch (e) {
    if (!mismatched(s, e)) throw e;
    // This device's own copy stays in use (read only) for its own vaults' checks; the server's isn't asked for again.
    if (!s.pins && localPins) setPinsRaw(s, localPins);
    s.pinsSeq = Math.max(s.pinsSeq, got);
    s.loaded = true;
    return;
  }
  if (pins) setPinsRaw(s, pins);
  s.pinsSeq = got;
  s.dirty = dirty;
  s.held = false;
  s.notice = null;
  s.loaded = true;
  saveLocal(s);
}

/** Whether two key pins hold the same (their `version` aside; key order doesn't matter). */
function samePins(a: KeyPins, b: KeyPins): boolean {
  const canon = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(canon)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, canon((v as Record<string, unknown>)[k])]),
          )
        : v;
  return JSON.stringify(canon({ ...a, version: 0 })) === JSON.stringify(canon({ ...b, version: 0 }));
}

/**
 * Two copies of this account's pins merged: unsent changes win (`mergePins(other, unsent)`); with none, the newer-based
 * copy (`a`) takes only what never goes back from the other (`pinsMergeLastKnown`). Throws `identity_mismatch`.
 */
function mergeCopies(a: KeyPins, aUnsent: boolean, b: KeyPins, bUnsent: boolean): KeyPins {
  if (bUnsent) return core.mergePins(a, b) as KeyPins;
  if (aUnsent) return core.mergePins(b, a) as KeyPins;
  return core.pinsMergeLastKnown(a, b) as KeyPins;
}

/**
 * `identity_mismatch` from a merge (the copies remember different own identities): pause sharing, and merge and write
 * nothing for this session (round 5). False for any other error.
 */
function mismatched(s: Session, e: unknown): boolean {
  if (errCode(e) !== "identity_mismatch") return false;
  s.frozen = true;
  s.held = true;
  pause(s);
  return true;
}

/**
 * Save the pins on this device (sealed, marked unsent while `dirty`). Only once the server showed it signs. A copy
 * another tab or window wrote meanwhile (not ours: the same or a higher version, or unsent changes at any version) is
 * merged in first, so its unsent changes aren't dropped; nothing is written over a stored copy that can't be read or
 * opened.
 */
function saveLocal(s: Session) {
  if (!s.pins || !s.proven || s.broken || s.frozen) return;
  const have = localPinsState(store, s.scope);
  if (have === "unreadable") return;
  if (have && have.sealed !== s.lastWritten && (have.seq >= s.pinsSeq || have.dirty)) {
    let theirs: KeyPins;
    try {
      theirs = s.account.openKeyPins(have.sealed, have.seq) as KeyPins;
    } catch {
      return;
    }
    try {
      // Theirs is based on the same or a newer server copy, or carries unsent changes (which win over a last-known copy).
      setPinsRaw(s, mergeCopies(theirs, have.dirty, s.pins, s.dirty));
    } catch (e) {
      mismatched(s, e);
      return;
    }
    // Their version is the server's they are based on; their unsent changes are ours to send now too.
    s.dirty = s.dirty || have.dirty;
    s.pinsSeq = Math.max(s.pinsSeq, have.seq);
  }
  try {
    const sealed = s.account.sealKeyPins({ ...s.pins, version: s.pinsSeq }, s.pinsSeq);
    if (writeLocalPins(store, s.scope, { seq: s.pinsSeq, sealed, dirty: s.dirty })) s.lastWritten = sealed;
  } catch {
    /* too large or locked: kept in memory, written to the server below */
  }
}

/** Replace the pins in memory (no save), tracking whether the pinned people changed (cached verdicts depend on them). */
function setPinsRaw(s: Session, pins: KeyPins) {
  s.pins = pins;
  const people = JSON.stringify(pins.pins ?? []);
  if (people !== s.peopleJson) {
    s.peopleJson = people;
    s.peopleVersion++;
  }
}

/**
 * A change to the pins: kept in memory, saved on this device at once (marked unsent), written to the server by
 * `flushPins`. Throws while this device's memory is unreadable (rule 7: pin writes throw).
 */
function setPins(s: Session, pins: KeyPins) {
  if (s.broken) throw new Error(MEMORY_UNREADABLE);
  setPinsRaw(s, pins);
  s.dirty = true;
  saveLocal(s);
}

/**
 * Write the key pins to the server when this device changed them: `seq` + 1 by compare-and-swap; when another device
 * wrote first (409 `key_pins_changed`), read theirs, merge this device's changes in and write once more. A failure
 * leaves them marked unsent (kept on this device) for the next sync. Never while the server's copy looked rolled back.
 */
export function flushPins(): Promise<void> {
  const s = session;
  // Nothing goes to the server before it showed it signs (review M-A), nor from a device whose memory is unreadable.
  if (!s || !s.dirty || s.held || s.frozen || !s.pins || !s.proven || s.broken) return Promise.resolve();
  if (s.flushing) return s.flushing;
  s.flushing = (async () => {
    for (let attempt = 0; attempt < 2 && session === s && s.dirty; attempt++) {
      const next = s.pinsSeq + 1;
      const pins = s.pins!;
      let sealed: string;
      try {
        sealed = s.account.sealKeyPins({ ...pins, version: next }, next);
      } catch {
        return;
      }
      try {
        await api("/account/key-pins", { method: "PUT", body: { key_pins: sealed, seq: next } });
        if (session !== s) return;
        s.pinsSeq = next;
        // Pins changed meanwhile (another check) stay marked unsent.
        if (s.pins === pins) s.dirty = false;
        saveLocal(s);
        return;
      } catch (e) {
        if (session !== s || !hasErrorCode(e, "key_pins_changed")) return;
        const r = await api<{ key_pins?: unknown; seq?: unknown } | null>("/account/key-pins").catch(() => null);
        if (session !== s || !r || !wholeNumber(r.seq)) return;
        if (r.seq < s.pinsSeq || typeof r.key_pins !== "string") {
          // Lower than a version this device wrote or read: rolled back. Keep this device's list and stop writing.
          s.held = true;
          s.notice = r.seq < s.pinsSeq ? PINS_ROLLED_BACK : PINS_UNREADABLE;
          return;
        }
        try {
          const theirs = s.account.openKeyPins(r.key_pins, r.seq) as KeyPins;
          // This device's changes are unsent: they win (`mergePins`).
          setPinsRaw(s, core.mergePins(theirs, s.pins!) as KeyPins);
          s.pinsSeq = r.seq;
          saveLocal(s);
        } catch (e) {
          mismatched(s, e);
          return;
        }
      }
    }
  })().finally(() => {
    if (session === s) s.flushing = null;
  });
  return s.flushing;
}

/**
 * Whether a v1 (legacy) account wrap of the vault at `keyEpoch` (the row's) may be opened (true without a session:
 * servers without the feature). Refused at or below the highest epoch this account opened from a v2 wrap.
 */
export function legacyWrapAllowed(vaultId: string, keyEpoch: number): boolean {
  const s = session;
  if (!s) return true;
  try {
    return core.pinsLegacyWrapAllowed(s.pins, vaultId, keyEpoch);
  } catch {
    return false;
  }
}

// ------------------------------------------------------------- people

/** How someone's identity compares with the account's pins (`self`: this account). */
export type PersonStatus = "new" | "match" | "upgraded" | "changed" | "email_conflict" | "invalid" | "self";

export interface PersonState {
  status: PersonStatus;
  /** Identity fingerprint (signing identities) or the older key fingerprint (legacy); null when it doesn't verify. */
  fingerprint: string | null;
  /** The identity hash (to check the identity shown is the one pinned later). */
  hash: string | null;
  verified: boolean;
  /** Has a signing identity. */
  signing: boolean;
  /** The email pinned with this user id (shown first); null when not pinned. */
  pinnedEmail: string | null;
}

/** An email as compared and shown: `normalizeEmail` (internationalized domains in punycode, so a look-alike can't pass for a known one), cleaned. */
export function emailText(email: unknown): string {
  const clean = cleanText(email);
  if (!clean) return "";
  try {
    return cleanText(core.normalizeEmail(clean));
  } catch {
    return clean;
  }
}

const pinOf = (s: Session | null, userId: string) => s?.pins?.pins.find((p) => p.user_id === userId) ?? null;

/** Someone's identity against the pins, without changing anything (for display). `listedEmail`: the server's. */
export function personState(identity: PublicIdentity, listedEmail?: string | null): PersonState {
  const s = session;
  const id = identityOf(identity);
  let info: core.IdentityInfo;
  try {
    info = core.verifyIdentity(id);
  } catch {
    return { status: "invalid", fingerprint: null, hash: null, verified: false, signing: false, pinnedEmail: null };
  }
  const fp = info.signing ? info.fingerprint : core.fingerprint(id.public_key);
  const base = { fingerprint: fp, hash: info.hash, signing: info.signing };
  if (!s) return { ...base, status: "new", verified: false, pinnedEmail: null };
  if (id.user_id === s.accountId) {
    const mine = s.identity ? s.identity.identityHash() : null;
    return { ...base, status: mine && mine === info.hash ? "self" : "changed", verified: false, pinnedEmail: null };
  }
  let status: PersonStatus;
  try {
    status = core.pinCheck(s.pins, id, listedEmail ? emailText(listedEmail) : null) as PersonStatus;
  } catch {
    return { ...base, status: "invalid", verified: false, pinnedEmail: null };
  }
  const pin = pinOf(s, id.user_id);
  return { ...base, status, verified: status === "match" && !!pin?.verified, pinnedEmail: pin ? emailText(pin.email) || null : null };
}

/**
 * "Mark as verified" (`mode: "verify"`: the identity shown is still the one pinned) or "Trust the new key" (`"trust"`:
 * the user compared the new fingerprint) for exactly the identity shown (`shownHash`). Pins it as verified; the pins
 * are written and every vault checked again at the next sync. Throws when the identity changed since it was shown.
 */
export function trustPerson(identity: PublicIdentity, email: string, opts: { mode: "verify" | "trust"; shownHash: string }) {
  const s = live();
  const id = identityOf(identity);
  const info = core.verifyIdentity(id);
  if (info.hash !== opts.shownHash) throw new Error("These keys changed since PassAuth showed them. Compare the fingerprint again.");
  if (opts.mode === "verify" && core.pinCheck(s.pins, id, null) !== "match") throw new Error("These keys changed since PassAuth showed them. Compare the fingerprint again.");
  // The email the dialog showed (iOS re-review): never one the server lists later.
  const pinned = pinOf(s, id.user_id);
  setPins(s, core.pinSet(s.pins, id, emailText(email) || emailText(pinned?.email), true, now()) as KeyPins);
  s.cache.clear();
}

/** Someone's keys changed since they were pinned (or a new account uses a pinned email). */
export class KeyChangedError extends Error {
  constructor(public change: KeyChange) {
    super(change.status === "email_conflict" ? emailConflictText(change.email) : keysChangedText(change.email));
  }
}

/** A share's signer, checked against the pins without pinning: the view, or the change that stops whatever needed them. */
function signerView(s: Session, signer: ShareSigner, deleted: boolean): { view: SignerView } | { change: KeyChange } {
  const id = identityOf(signer);
  const info = core.verifyIdentity(id); // throws bad_signature
  const listed = emailText(signer.email);
  const status = core.pinCheck(s.pins, id, listed || null);
  const pin = pinOf(s, id.user_id);
  const pinned = pin ? emailText(pin.email) || null : null;
  const label = pinned || listed || signer.name || "someone on this server";
  if (status === "changed" || status === "email_conflict")
    return { change: { identity: id, email: label, fingerprint: info.fingerprint, hash: info.hash, status } };
  return {
    view: {
      identity: id,
      label,
      email: pinned || listed,
      listedAs: listedAs(pinned, listed),
      fingerprint: info.fingerprint,
      hash: info.hash,
      pin: status,
      verified: status === "match" && !!pin?.verified,
      deleted,
    },
  };
}

/**
 * Pin a checked signer when the pins don't know them yet (with `email`, the one shown, in `normalizeEmail` form), or
 * when their legacy identity got a signing key (`upgraded`: the pinned email and its "verified" are kept, rule 4).
 */
function pinSigner(s: Session, v: SignerView, email: string) {
  if (v.pin === "new") setPins(s, core.pinSet(s.pins, v.identity, emailText(email), false, now()) as KeyPins);
  else if (v.pin === "upgraded") pinUpgraded(s, v.identity, email);
}

/** Re-pin an upgraded identity (the same X25519 key, now cross-signed) keeping the pinned email and whether it was verified. */
function pinUpgraded(s: Session, identity: PublicIdentity, fallbackEmail: string) {
  const old = pinOf(s, identity.user_id);
  setPins(s, core.pinSet(s.pins, identity, emailText(old?.email) || emailText(fallbackEmail), !!old?.verified, now()) as KeyPins);
}

// -------------------------------------------------------------- rosters

class CheckLaterError extends Error {
  constructor() {
    super(CHECK_LATER);
  }
}
class TooManyError extends Error {
  constructor() {
    super(TOO_MANY_CHANGES);
  }
}

/** The roster history couldn't be fetched (no connection, the server failing): checked again at the next sync. */
export const CHECK_LATER = "PassAuth couldn't check this shared vault with your server just now, so it isn't used yet. It's checked again at the next sync.";

/** Every roster of a vault after version `after`, oldest first, within the caps (1000 versions, 10 pages, 16 MiB). */
async function fetchRosters(vaultId: string, after: number): Promise<string[]> {
  const out: string[] = [];
  let bytes = 0;
  for (let page = 0; page < ROSTER_PAGES_MAX; page++) {
    let answer: unknown;
    try {
      answer = await api(`/vaults/${encodeURIComponent(vaultId)}/rosters?after=${after}`);
    } catch {
      throw new CheckLaterError();
    }
    const r = readRostersPage(answer);
    if (!r) throw new Error(VAULT_REFUSED);
    for (const text of r.rosters) {
      bytes += text.length;
      out.push(text);
    }
    if (out.length > ROSTER_VERSIONS_MAX || bytes > ROSTER_BYTES_MAX) throw new TooManyError();
    if (!r.more) return out;
    if (r.rosters.length === 0) throw new Error(VAULT_REFUSED);
    after = rosterNumbers(r.rosters[r.rosters.length - 1])?.version ?? after + r.rosters.length;
  }
  throw new TooManyError();
}

/** The roster this device can trust, and `chain_hashes` when a chain was fetched to get there (null otherwise). */
interface Trusted {
  roster: string | null;
  chain: Record<string, string> | null;
}

/**
 * The member roster this device can trust for `vaultId` whose latest is `latest` (null: none): the remembered one when
 * the server's is the same, else the chain after it (fetched within the caps and verified, from version 1 when nothing
 * is remembered) up to exactly `latest`. Null when neither has one. Throws when it rolled back, forked or doesn't verify.
 * With a fetched chain, `chain` = `rosterHash` per version of the roster it started from and every roster verified
 * (round 4 `chain_hashes`: admission checks it against the roster the account pinned). Remembers nothing: the caller
 * does once every check of the row passed.
 */
async function trustRoster(vaultId: string, remembered: string | null, latest: string | null): Promise<Trusted> {
  const head = core.rosterHead(vaultId, remembered, latest);
  if (head.status === "unsigned") return { roster: null, chain: null };
  if (head.status === "same") return { roster: remembered, chain: null };
  const newer = await fetchRosters(vaultId, head.after);
  const roster = core.verifyRosterChain(vaultId, remembered, newer, latest!);
  return { roster, chain: chainHashes([...(remembered ? [remembered] : []), ...newer]) };
}

/** `{"<version>": rosterHash}` of verified rosters (versions as plain decimal numbers). */
function chainHashes(rosters: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rosters) {
    const n = rosterNumbers(r);
    if (!n) throw new Error(VAULT_REFUSED);
    out[String(n.version)] = core.rosterHash(r);
  }
  return out;
}

function remember(s: Session, vaultId: string, patch: VaultMemory) {
  if (!s.proven) return;
  updateMemory(store, s.scope, { vaults: { [vaultId]: patch } });
}

// ---------------------------------------------------------- verification

/**
 * Check every vault row and invitation of a sync (steps 1–3). At the account's first signed sync the vaults it has now
 * are grandfathered (once). Verdicts are cached per row while the row, this account's identity, the remembered roster,
 * the vault's pins and the pinned people stay the same. Pins this check changes are written with `flushPins`.
 */
export async function verifySnapshot(vaults: readonly SignedVaultRow[], invitations: readonly SignedInvitationRow[]): Promise<Verdicts | null> {
  const s = session;
  if (!s) return null;
  const out: Verdicts = { vaults: new Map(), invitations: new Map() };
  const unwritten = s.pins?.grandfathered === null || s.pins?.grandfathered === undefined;
  if (s.loaded && !s.held && !s.paused && !s.broken && s.proven && unwritten && !s.skipGrandfather && (s.createdIdentity || s.identity)) {
    // The account's first signed sync, with the identity state known. When this unlock made the signing identity, the
    // unsigned shares it has now that were already on this device in an earlier session stay usable ("Not yet signed");
    // a device with no earlier record grandfathers nothing (a server could fake "created" to it): each shared vault
    // waits for consent, like when the trust memory is missing (review M-B). An identity from before with no key pins
    // (withheld, or never written) is a missing trust memory: nothing is grandfathered, every shared vault needs consent.
    const sealed = vaults.filter((r) => r.key_kind === "sealed").map((r) => r.id);
    if (s.createdIdentity) {
      // The vaults this device had shown as usable when the identity was first generated here (rule 6), else (an
      // identity made before that record existed) the ones recorded before this unlock. Each with the key id it has
      // now: only that key is grandfathered (round 5).
      const recorded = readMemory(store, s.scope).earlier;
      const before = recorded !== undefined ? recorded : earlierSeen(s.scope);
      setPins(s, core.pinsGrandfather(s.pins, before ? grandfatherCandidates(s, vaults, before) : [], true) as KeyPins);
      if (!before) setMissing(s, sealed, "device");
    } else {
      // Trust memory missing: nothing is grandfathered (the core writes an empty list).
      setPins(s, core.pinsGrandfather(s.pins, [], false) as KeyPins);
      setMissing(s, sealed, "pins");
    }
  }
  // The first signed sync is finished (the pins hold the own identity and the grandfathered list): the identity
  // generated here and the vaults recorded with it are no longer needed (rule 6).
  if (s.proven && !s.broken && s.pins?.own_identity && s.pins.grandfathered !== null && s.pins.grandfathered !== undefined) {
    const m = readMemory(store, s.scope);
    if (m.generated.length || m.earlier !== undefined) updateMemory(store, s.scope, { clearPending: true });
  }
  s.rows = new Set(vaults.map((r) => r.id));
  // Built aside and swapped in at the end: a change planned meanwhile sees the last complete sync's state.
  const verified = new Map<string, { roster: string | null; epoch: number }>();
  for (const row of vaults) {
    const key = vaultCacheKey(s, row);
    const hit = s.cache.get(`v:${row.id}`);
    if (hit?.key === key) {
      const verdict = hit.verdict as VaultVerdict;
      out.vaults.set(row.id, verdict);
      if (verdict.status === "ok") verified.set(row.id, { roster: hit.roster ?? null, epoch: hit.epoch ?? 0 });
      continue;
    }
    const { verdict, roster, epoch } = await verifyVault(s, row);
    if (session !== s) return null;
    // A failure to reach the server, or a vault held until the first signed sync is finished, isn't a verdict about
    // the vault: not cached.
    if (!(verdict.status === "refused" && (verdict.reason === CHECK_LATER || verdict.reason === STILL_CHECKING)))
      s.cache.set(`v:${row.id}`, { key: vaultCacheKey(s, row), verdict, roster, epoch });
    out.vaults.set(row.id, verdict);
    if (verdict.status === "ok") verified.set(row.id, { roster: roster ?? null, epoch: epoch ?? 0 });
  }
  s.verified = verified;
  settleMissing(s, out.vaults);
  await tombstoneGone(s, vaults, invitations);
  if (session !== s) return null;
  for (const inv of invitations) {
    const key = invitationCacheKey(s, inv);
    const hit = s.cache.get(`i:${inv.vault_id}`);
    if (hit?.key === key) {
      out.invitations.set(inv.vault_id, hit.verdict as InvitationTrust);
      continue;
    }
    const trust = s.paused
      ? ({ kind: "refused", reason: SHARING_PAUSED } as const)
      : s.broken
        ? ({ kind: "refused", reason: MEMORY_UNREADABLE } as const)
        : await verifyInvitation(s, inv);
    if (session !== s) return null;
    if (!(trust.kind === "refused" && trust.reason === CHECK_LATER)) s.cache.set(`i:${inv.vault_id}`, { key: invitationCacheKey(s, inv), verdict: trust });
    out.invitations.set(inv.vault_id, trust);
  }
  return out;
}

/**
 * The grandfathering candidates: the unsigned rows among `ids`, each with the key id (`VaultKey.keyId`) of the key it
 * has now (a row whose key doesn't open is left out: it is checked like any other).
 */
function grandfatherCandidates(s: Session, vaults: readonly SignedVaultRow[], ids: readonly string[]): core.GrandfatherCandidate[] {
  const out = new Map<string, string>();
  for (const r of vaults) {
    if ((r.share !== null && r.share !== undefined) || !ids.includes(r.id) || out.has(r.id)) continue;
    const kind = r.key_kind === "account" || r.key_kind === "sealed" ? r.key_kind : null;
    if (!kind || !wholeNumber(r.key_epoch)) continue;
    try {
      const key = s.account.openVaultKey(r.id, r.wrapped_key, kind, r.key_epoch, core.pinsLegacyWrapAllowed(s.pins, r.id, r.key_epoch));
      try {
        out.set(r.id, key.keyId(r.id));
      } finally {
        key.free();
      }
    } catch {
      /* not openable: not grandfathered */
    }
  }
  return [...out].map(([vault_id, key_id]) => ({ vault_id, key_id }));
}

/** The vaults waiting without trust memory, written once (device memory `missing`; only shrinks after). */
function setMissing(s: Session, ids: string[], why: "pins" | "device") {
  const m = s.proven ? updateMemory(store, s.scope, { missing: { ids, why } }) : null;
  s.missing = new Set(m?.missing ?? ids);
  s.missingWhy = m?.missingWhy ?? why;
}

/**
 * After a sync's checks: a vault no longer waiting (accepted, declined, gone) leaves the `missing` list; the notice says
 * why consent is asked while any of them still waits.
 */
function settleMissing(s: Session, verdicts: Map<string, VaultVerdict>) {
  if (s.missing.size === 0) {
    s.missingNotice = null;
    return;
  }
  const waiting = [...s.missing].filter((id) => {
    const v = verdicts.get(id);
    return v?.status === "consent" || (v?.status === "refused" && v.reason === CHECK_LATER);
  });
  if (waiting.length !== s.missing.size) {
    s.missing = new Set(waiting);
    if (s.proven) updateMemory(store, s.scope, { missing: { ids: waiting, why: s.missingWhy } });
  }
  s.missingNotice = waiting.some((id) => verdicts.get(id)?.status === "consent") ? (s.missingWhy === "device" ? NEW_DEVICE : TRUST_MEMORY_MISSING) : null;
}

/**
 * An accepted shared vault verified syncs no longer list (the account left, was removed or the vault was deleted):
 * tombstoned with the roster version this device trusted, so the server can't bring it back unless it is shared again
 * with a newer member list. A removal is observed, not assumed (rule 3): only once the vault is absent from two
 * consecutive verified syncs, or its members request answers 404 — never after one sync that omitted it. Not while
 * paused (nothing is verified then) or before the server showed it signs.
 */
async function tombstoneGone(s: Session, vaults: readonly SignedVaultRow[], invitations: readonly SignedInvitationRow[]) {
  if (!s.proven || s.paused || s.broken || !s.loaded || !s.pins?.epochs) return;
  const listed = new Set([...vaults.map((r) => r.id), ...invitations.map((i) => i.vault_id)]);
  for (const id of [...s.absent.keys()]) if (listed.has(id)) s.absent.delete(id);
  for (const vaultId of Object.keys(s.pins.epochs)) {
    // Only vaults this session saw shared WITH me (sealed). A vault I own (account-wrapped) that a server leaves out of
    // a sync must never be tombstoned: a `left` tombstone would refuse my own vault for good.
    if (listed.has(vaultId) || s.pins.left?.[vaultId] || !s.sharedSeen.has(vaultId)) continue;
    const count = (s.absent.get(vaultId) ?? 0) + 1;
    s.absent.set(vaultId, count);
    let confirmed = count >= 2;
    if (!confirmed) {
      confirmed = await membershipGone(vaultId);
      if (session !== s) return;
    }
    const pin = s.pins?.epochs?.[vaultId];
    if (!confirmed || !pin || s.pins?.left?.[vaultId]) continue;
    const m = readMemory(store, s.scope).vaults[vaultId];
    const version = Math.max(m?.roster ? (rosterNumbers(m.roster)?.version ?? 0) : 0, pin.roster_version_max ?? 0, pin.signed_since ?? 0);
    try {
      setPins(s, core.pinsLeave(s.pins, vaultId, version, now()) as KeyPins);
      s.absent.delete(vaultId);
    } catch {
      /* too large: tried again at the next sync */
    }
    s.cache.delete(`v:${vaultId}`);
  }
}

/** Whether the server says this account is no longer in the vault (its members request answers 404; a 403 can be a two-step or re-auth refusal, so it doesn't count). */
async function membershipGone(vaultId: string): Promise<boolean> {
  try {
    await api(`/vaults/${encodeURIComponent(vaultId)}/members`);
    return false;
  } catch (e) {
    const st = statusOf(e);
    return st === 404;
  }
}

/** Everything a vault's verdict depends on besides the row: who I am, the remembered roster, the vault's pins, the people. */
function vaultState(s: Session, vaultId: string): unknown[] {
  const memory = readMemory(store, s.scope).vaults[vaultId];
  return [
    s.me.signing_key,
    s.paused,
    memory?.roster ?? null,
    memory?.signed ?? false,
    s.pins?.epochs?.[vaultId] ?? null,
    s.pins?.left?.[vaultId] ?? null,
    s.pins?.grandfathered?.[vaultId] ?? null,
    s.missing.has(vaultId),
    s.peopleVersion,
  ];
}

const vaultCacheKey = (s: Session, row: SignedVaultRow) =>
  JSON.stringify(["v", row.id, row.role, row.wrapped_key, row.key_kind, row.key_epoch, row.member_roster_seq, row.member_roster, row.share, ...vaultState(s, row.id)]);
const invitationCacheKey = (s: Session, inv: SignedInvitationRow) =>
  JSON.stringify(["i", inv.vault_id, inv.role, inv.wrapped_key, inv.key_epoch, inv.member_roster, inv.share, ...vaultState(s, inv.vault_id)]);

const refuse = (reason = VAULT_REFUSED, changed?: KeyChange): VaultVerdict => ({ status: "refused", reason, ...(changed ? { changed } : {}) });

/** A failure while fetching or checking rosters, as a refusal. */
function rosterFailure(e: unknown): string {
  if (e instanceof CheckLaterError) return CHECK_LATER;
  if (e instanceof TooManyError || errCode(e) === "too_large") return TOO_MANY_CHANGES;
  return VAULT_REFUSED;
}

interface RowResult {
  verdict: VaultVerdict;
  roster?: string | null;
  epoch?: number;
}

async function verifyVault(s: Session, row: SignedVaultRow): Promise<RowResult> {
  const kind = row.key_kind === "account" || row.key_kind === "sealed" ? row.key_kind : null;
  const latest = readRosterText(row.member_roster);
  const share = readShare(row.share);
  if (!kind || latest === MALFORMED || share === MALFORMED) return { verdict: refuse() };
  // Unreadable device memory (rule 7): shared vaults aren't used; own vaults are still checked against the server's pins.
  if (kind === "sealed" && s.broken) return { verdict: refuse(MEMORY_UNREADABLE) };
  const paused = !!s.paused;
  if (!wholeNumber(row.key_epoch)) {
    const a = core.pinsAdmit(s.pins, { vault_id: row.id, key_kind: kind, key: null, roster_version: null, roster_hash: null, signed_share: false, paused });
    return { verdict: refuse(a.status === "refused" ? refusedText(a.reason) : VAULT_REFUSED) };
  }
  const epoch = row.key_epoch;
  const memory = readMemory(store, s.scope).vaults[row.id];
  // (b) The roster chain, within the caps, ending exactly at the row's.
  let trusted: string | null;
  let chain: Record<string, string> | null;
  try {
    ({ roster: trusted, chain } = await trustRoster(row.id, memory?.roster ?? null, latest));
  } catch (e) {
    return { verdict: refuse(rosterFailure(e)) };
  }
  if (session !== s) return { verdict: refuse() };
  // (a) The key, with the row's epoch.
  let key: core.VaultKey;
  try {
    key = s.account.openVaultKey(row.id, row.wrapped_key, kind, epoch, core.pinsLegacyWrapAllowed(s.pins, row.id, epoch));
  } catch {
    return { verdict: refuse(kind === "account" ? VAULT_UNOPENABLE : VAULT_REFUSED) };
  }
  // An own wrap bound to its epoch (v2) opened: observed as such, so v1 wraps at or below this epoch are refused later.
  let boundWrap = false;
  if (kind === "account") {
    try {
      boundWrap = core.accountWrapIsBound(row.wrapped_key);
    } catch {
      boundWrap = false;
    }
  }
  let rosterVersion: number | null = null;
  let current: core.EpochPin;
  try {
    if (trusted) {
      const n = rosterNumbers(trusted);
      if (!n || n.keyEpoch !== epoch || !key.matchesRoster(row.id, trusted)) return { verdict: refuse() };
      // The roster lists me with my row's role (paused: my signing identity isn't known, so this is left to the key checks).
      if (!paused && core.rosterMemberRole(trusted, s.me) !== row.role) return { verdict: refuse() };
      rosterVersion = n.version;
    }
    current = key.epochPin(row.id, epoch);
  } catch {
    return { verdict: refuse() };
  } finally {
    key.free();
  }
  // (c) A sealed key's share: its signer verified and pin-checked (not pinned yet), the signature, the signer's authority.
  let signer: SignerView | null = null;
  let signedShare = false;
  if (kind === "sealed" && share && !paused) {
    try {
      const checked = signerView(s, share.signer, share.signerDeleted);
      if ("change" in checked) return { verdict: refuse(checked.change.status === "email_conflict" ? emailConflictText(checked.change.email) : keysChangedText(checked.change.email), checked.change) };
      core.verifyShare(row.id, s.me, row.role, epoch, row.wrapped_key, checked.view.identity, share.signature);
      if (trusted) {
        const role = core.rosterSignerRole(trusted, checked.view.identity);
        if (role !== "owner" && role !== "admin") return { verdict: refuse() };
      }
      signer = checked.view;
      signedShare = true;
    } catch {
      return { verdict: refuse() };
    }
  }
  // (d) Admission (`pinsObserve`: the verdict, and the pins with what it says to pin applied).
  let observed: core.Observed;
  try {
    observed = core.pinsObserve(s.pins, {
      vault_id: row.id,
      key_kind: kind,
      key: current,
      roster_version: rosterVersion,
      roster_hash: trusted ? core.rosterHash(trusted) : null,
      // Whenever a chain was fetched: a chain re-signed from version 1 can't hide the roster the account pinned.
      ...(chain ? { chain_hashes: chain } : {}),
      signed_share: signedShare,
      paused,
      ...(boundWrap ? { bound_wrap: true } : {}),
    });
  } catch {
    return { verdict: refuse() };
  }
  const a = observed.admission;
  if (a.status === "refused") return { verdict: refuse(refusedText(a.reason)) };
  if (a.status === "consent") {
    // Rule 2: before this device finished the account's first signed sync, an unsigned shared vault isn't offered for
    // consent (nor declined): held neutrally until the server proved it signs and the grandfathered list is written.
    if (!signedShare && !firstSignedSyncDone(s)) return { verdict: refuse(STILL_CHECKING) };
    return {
      verdict: {
        status: "consent",
        consent: {
          vaultId: row.id,
          role: row.role,
          rejoin: a.rejoin,
          replaced: a.replaced,
          own: a.own === true,
          firstSigned: a.first_signed === true,
          declinable: a.declinable === true,
          unsignedAllowed: s.missing.has(row.id),
          signer,
          roster: trusted,
          rosterVersion,
          chainHashes: chain,
          epoch: current,
        },
      },
    };
  }
  // Every check passed: only now are the pins and the memory written (never while the device memory is unreadable:
  // own vaults are then checked read only).
  const trust: VaultTrust = a.trust === "own" ? { kind: "own" } : a.trust === "signed" ? { kind: "signed", signer } : { kind: "unsigned" };
  if (s.broken) return { verdict: { status: "ok", trust, rosterSeq: rosterVersion ?? 0 }, roster: trusted, epoch };
  try {
    if (observed.changed) setPins(s, observed.pins);
    if (signer && share) pinSigner(s, signer, signer.email);
  } catch {
    return { verdict: refuse() };
  }
  if (trusted || a.trust === "signed") remember(s, row.id, { ...(trusted ? { roster: trusted } : {}), ...(a.trust === "signed" ? { signed: true } : {}) });
  if (kind === "sealed") s.sharedSeen.add(row.id);
  return { verdict: { status: "ok", trust, rosterSeq: rosterVersion ?? 0 }, roster: trusted, epoch };
}

async function verifyInvitation(s: Session, inv: SignedInvitationRow): Promise<InvitationTrust> {
  const share = readShare(inv.share);
  if (share === null) return { kind: "unsigned" };
  const refused = (reason = VAULT_REFUSED, changed?: KeyChange): InvitationTrust => ({ kind: "refused", reason, ...(changed ? { changed } : {}) });
  const latest = readRosterText(inv.member_roster);
  if (share === MALFORMED || latest === MALFORMED || latest === null || !wholeNumber(inv.key_epoch)) return refused();
  const epoch = inv.key_epoch;
  let view: SignerView;
  try {
    const checked = signerView(s, share.signer, share.signerDeleted);
    if ("change" in checked)
      return refused(checked.change.status === "email_conflict" ? emailConflictText(checked.change.email) : keysChangedText(checked.change.email), checked.change);
    view = checked.view;
    core.verifyShare(inv.vault_id, s.me, inv.role, epoch, inv.wrapped_key, view.identity, share.signature);
  } catch {
    return refused();
  }
  // The invitation's roster chain, as a member checks it; remembered only when the invitation is accepted.
  let roster: string;
  let chain: Record<string, string> | null;
  try {
    const t = await trustRoster(inv.vault_id, readMemory(store, s.scope).vaults[inv.vault_id]?.roster ?? null, latest);
    if (!t.roster) return refused();
    roster = t.roster;
    chain = t.chain;
  } catch (e) {
    return refused(rosterFailure(e));
  }
  if (session !== s) return refused();
  let current: core.EpochPin;
  let n: { version: number; keyEpoch: number } | null;
  try {
    const signerRole = core.rosterSignerRole(roster, view.identity);
    if (signerRole !== "owner" && signerRole !== "admin") return refused();
    if (core.rosterMemberRole(roster, s.me) !== inv.role) return refused();
    n = rosterNumbers(roster);
    if (!n || n.keyEpoch !== epoch) return refused();
    const key = s.account.openVaultKey(inv.vault_id, inv.wrapped_key, "sealed", epoch, false);
    try {
      if (!key.matchesRoster(inv.vault_id, roster)) return refused();
      current = key.epochPin(inv.vault_id, epoch);
    } finally {
      key.free();
    }
  } catch {
    return refused();
  }
  let a: core.Admission;
  try {
    a = core.pinsAdmit(s.pins, {
      vault_id: inv.vault_id,
      key_kind: "sealed",
      key: current,
      roster_version: n.version,
      roster_hash: core.rosterHash(roster),
      ...(chain ? { chain_hashes: chain } : {}),
      signed_share: true,
      paused: !!s.paused,
      // Never grandfathered, never the account's own vault, `held` for a vault it holds (round 5).
      invitation: true,
    });
  } catch {
    return refused();
  }
  if (a.status === "refused") return refused(refusedText(a.reason));
  const c = a.status === "consent" ? a : null;
  return {
    kind: "signed",
    signer: view,
    roster,
    rosterVersion: n.version,
    chainHashes: chain,
    epoch: current,
    rejoin: c?.rejoin === true,
    replaced: c?.replaced === true,
    own: c?.own === true,
    firstSigned: c?.first_signed === true,
    held: c?.held === true,
    declinable: c ? c.declinable === true : true,
  };
}

/**
 * Whether this device finished the account's first signed sync: the server showed it signs, the identity state is known
 * (the own signing identity opened), and the key pins hold the grandfathered list (rule 2).
 */
function firstSignedSyncDone(s: Session): boolean {
  return s.proven && s.loaded && !s.paused && !s.broken && !!s.identity && s.pins?.grandfathered !== null && s.pins?.grandfathered !== undefined;
}

/** What an accept pins: the vault's key as checked, with the roster (and the chain fetched) the dialog showed. */
interface Shown {
  signer: SignerView | null;
  roster: string | null;
  rosterVersion: number | null;
  chainHashes: Record<string, string> | null;
  epoch: core.EpochPin;
  /** The admission flags the dialog showed (the wording depends on them): accepted only while they are the same. */
  rejoin?: boolean;
  replaced?: boolean;
  own?: boolean;
  firstSigned?: boolean;
  held?: boolean;
  declinable?: boolean;
}

/**
 * Accept a signed invitation or a vault needing consent (`pinsAccept`: the same admission again, then the key pinned
 * with the roster's hash; clears a tombstone and marks the re-join), pin its signer with exactly the email the dialog
 * showed (rule 4), and remember its roster. Nothing is written when the core refuses.
 */
function admit(s: Session, vaultId: string, shown: Shown, invitation = false) {
  let accepted: KeyPins;
  try {
    accepted = core.pinsAccept(s.pins, {
      vault_id: vaultId,
      key_kind: "sealed",
      key: shown.epoch,
      roster_version: shown.rosterVersion,
      roster_hash: shown.roster ? core.rosterHash(shown.roster) : null,
      ...(shown.chainHashes ? { chain_hashes: shown.chainHashes } : {}),
      signed_share: !!shown.signer,
      paused: !!s.paused,
      // The same observation the invitation's admission saw, so the flags shown are the flags accepted.
      ...(invitation ? { invitation: true } : {}),
    }) as KeyPins;
  } catch {
    // rollback (left, older, conflict, downgraded), roster_forked, identity_mismatch: what admission would refuse.
    throw new Error(VAULT_REFUSED);
  }
  setPins(s, accepted);
  if (shown.signer) pinSigner(s, shown.signer, shown.signer.email);
  if (shown.roster || shown.signer) remember(s, vaultId, { ...(shown.roster ? { roster: shown.roster } : {}), ...(shown.signer ? { signed: true } : {}) });
  s.cache.delete(`v:${vaultId}`);
}

/** Accepting something that changed since its dialog showed it. */
export const CHANGED_SINCE_SHOWN = "This vault changed since PassAuth showed it. Look at it again, then decide.";

/**
 * What a consent or invitation dialog showed: the signer (identity hash and the email and name shown: an accept pins
 * exactly that email, rule 4), key id and epoch, and the member roster with the chain checked (review L-B).
 */
function shownKey(x: Shown): string {
  let rosterHash: string | null = null;
  try {
    rosterHash = x.roster ? core.rosterHash(x.roster) : null;
  } catch {
    rosterHash = "unreadable";
  }
  const chain = x.chainHashes ? Object.entries(x.chainHashes).sort(([a], [b]) => Number(a) - Number(b)) : null;
  const flags = [x.rejoin, x.replaced, x.own, x.firstSigned, x.held, x.declinable].map((f) => f === true);
  return JSON.stringify([x.signer?.hash ?? null, x.signer?.email ?? null, x.signer?.label ?? null, x.epoch?.key_id ?? null, x.epoch?.key_epoch ?? null, rosterHash, x.rosterVersion, chain, flags]);
}

/** Whether a vault needing consent is still exactly what was shown (signer and their email, key id, epoch, roster, role, kind). */
export const sameConsent = (a: Consent, b: Consent): boolean =>
  a.vaultId === b.vaultId &&
  a.role === b.role &&
  a.replaced === b.replaced &&
  a.own === b.own &&
  a.rejoin === b.rejoin &&
  a.unsignedAllowed === b.unsignedAllowed &&
  shownKey(a) === shownKey(b);

/** Whether a signed invitation is still exactly what was shown. */
export const sameInvitationTrust = (a: InvitationTrust | undefined, b: InvitationTrust | undefined): boolean =>
  a?.kind === "signed" && b?.kind === "signed" && shownKey(a) === shownKey(b);

/**
 * The user accepts a signed invitation that passed every check in this sync, exactly as its dialog showed it (`shown`,
 * captured when the dialog opened): a different signer, key id, epoch or roster now throws `CHANGED_SINCE_SHOWN`.
 */
export function acceptInvitationTrust(vaultId: string, trust: Extract<InvitationTrust, { kind: "signed" }>, shown: InvitationTrust = trust) {
  const s = live();
  if (!sameInvitationTrust(trust, shown) || shown.kind !== "signed") throw new Error(CHANGED_SINCE_SHOWN);
  admit(s, vaultId, shown, true);
}

/** Whether a vault needing consent may be accepted: signed, a replaced key, or unsigned while trust memory is missing (rule 1). */
export const consentAcceptable = (c: Consent): boolean => !!c.signer || c.replaced || c.unsignedAllowed;

/**
 * Whether a vault needing consent may be declined: only where the core says `declinable` (signed, and none of re-join,
 * replaced, own, first signed, held: a puppet-signed consent for a vault the account uses must not lead the user into
 * giving it up, round 5 M2), and only a signed one that names its signer (rule 1). Otherwise "Not now".
 */
export const consentDeclinable = (c: Consent): boolean => c.declinable && !!c.signer;

/** Whether a signed invitation may be declined (`declinable`); unsigned and refused ones always may (nothing is tombstoned). */
export const invitationDeclinable = (t: InvitationTrust | undefined): boolean => t?.kind !== "signed" || t.declinable;

/**
 * The user accepts a vault needing consent: a signed one (its signer and key pinned, roster remembered); an unsigned one
 * only when its key was replaced (`replaced`) or while the trust memory is missing, by the key id shown.
 */
export function acceptConsent(consent: Consent, shown: Consent = consent) {
  const s = live();
  if (!sameConsent(consent, shown)) throw new Error(CHANGED_SINCE_SHOWN);
  if (!consentAcceptable(shown)) throw new Error(`This vault isn't signed, so it can't be accepted. ${ASK_OWNER_TO_SIGN}`);
  admit(s, shown.vaultId, shown);
  if (!shown.signer && s.missing.delete(shown.vaultId) && s.proven) updateMemory(store, s.scope, { missing: { ids: [...s.missing], why: s.missingWhy } });
}

/**
 * The account leaves or deletes a vault: its key pin becomes a tombstone (at the roster version this device trusts), so
 * the vault served again is refused unless shared again with a newer member list. Nothing is written before the server
 * showed it signs, or while this device's memory is unreadable.
 */
export function markLeft(vaultId: string) {
  const s = session;
  // Also while paused (the pins don't need the signing identity): the tombstone is what keeps the vault out later.
  if (!s || !s.loaded || !s.proven || s.broken || s.frozen) return;
  const version = rosterNumbers(s.verified.get(vaultId)?.roster ?? readMemory(store, s.scope).vaults[vaultId]?.roster ?? "")?.version ?? 0;
  try {
    setPins(s, core.pinsLeave(s.pins, vaultId, version, now()) as KeyPins);
  } catch {
    /* too large: refused at the next write too; the server's own state still removes the membership */
  }
  s.cache.delete(`v:${vaultId}`);
}

/**
 * The user declined a signed invitation or a vault needing consent (`pinsDecline`, round 5 M2): a tombstone at roster
 * version 0 (never a server-chosen version), and only for a vault the account doesn't hold: nothing changes when it
 * has an epoch pin, was left already, or is one of the last sync's vault rows (whatever its verdict).
 */
export function markDeclined(vaultId: string) {
  const s = session;
  if (!s || !s.loaded || !s.proven || s.broken || s.frozen) return;
  try {
    const next = core.pinsDecline(s.pins, vaultId, s.rows.has(vaultId), now()) as KeyPins;
    if (!s.pins || !samePins(next, s.pins)) setPins(s, next);
  } catch {
    /* too large: nothing written */
  }
  s.cache.delete(`v:${vaultId}`);
  s.cache.delete(`i:${vaultId}`);
}

/**
 * A key this device itself just gave a vault and the server accepted (its own key replacement, or re-signing at the
 * current key): pinned with the roster it signed (version and hash together, or neither), so this device never asks
 * about its own key (`pinsRecordRotation`). `keyKind`: this account's own row's (`account`, or `sealed`). Kept unsent
 * on this device until written.
 */
export function recordOwnKey(vaultId: string, keyKind: string, current: core.EpochPin, roster: string | null) {
  const s = session;
  if (!s || !s.loaded || !s.proven || s.broken || s.frozen || s.paused) return;
  const version = roster ? (rosterNumbers(roster)?.version ?? null) : null;
  try {
    setPins(s, core.pinsRecordRotation(s.pins, vaultId, keyKind, current, version, version === null ? null : core.rosterHash(roster!)) as KeyPins);
  } catch {
    /* refused (an older key, a vault left, a forked roster) or too large: the next sync's checks decide */
  }
  s.cache.delete(`v:${vaultId}`);
}

/** A roster this account just signed and the server stored: trusted as it is (signed here, after the review). */
export function rememberSigned(vaultId: string, roster: string) {
  const s = session;
  if (s) remember(s, vaultId, { roster, signed: true });
}

function live(): Session {
  const s = session;
  if (!s) throw new Error("The vault is locked. Unlock it and try again.");
  if (s.paused) throw new Error(s.paused);
  if (s.broken) throw new Error(MEMORY_UNREADABLE);
  return s;
}

/**
 * For emergency access: whether this device has any sign the vault is shared with others: a roster it trusts (from this
 * sync, or remembered) lists anyone but this account, it was seen signed, or the account's pin marks it signed.
 */
export function sharedEvidence(vaultId: string): boolean {
  const s = session;
  if (!s) return false;
  const memory = readMemory(store, s.scope).vaults[vaultId];
  const rosters = [s.verified.get(vaultId)?.roster ?? null, memory?.roster ?? null].filter((r): r is string => !!r);
  if (rosters.some((r) => rosterUserIds(r).some((u) => u !== s.accountId))) return true;
  if (memory?.signed) return true;
  const pin = s.pins?.epochs?.[vaultId];
  return !!pin && pin.signed_since !== null && pin.signed_since !== undefined;
}

// --------------------------------------------------------- signed writes

/** The signing identity for a write; throws when this device can't sign (paused, or not set up yet). */
function signer(): { s: Session; identity: core.SigningIdentity } {
  const s = live();
  if (!s.identity) throw new Error("PassAuth is still setting up signing on this device. Wait a moment, then try again.");
  return { s, identity: s.identity };
}

/** The roster this sync verified for a vault (null: none), or undefined when the vault didn't pass this sync's checks. */
export function verifiedRoster(vaultId: string): string | null | undefined {
  return session?.verified.get(vaultId)?.roster;
}

/** The member list a change will sign, as the user confirmed it: the review's digest and the missing people's user ids. */
export interface Confirmation {
  digest: string;
  missing: string[];
  /**
   * The email the review showed per member (user id → email; the digest covers user id, identity and role only): the
   * people pinned after the review get these, never ones from a later members answer.
   */
  emails?: Record<string, string>;
}

/** A member review as the app shows it (names cleaned, pinned email first). */
export interface ReviewView {
  vaultId: string;
  digest: string;
  /** No trusted roster yet: the version-1 review. */
  first: boolean;
  version: number;
  members: {
    userId: string;
    role: string;
    fingerprint: string;
    isSelf: boolean;
    pin: string;
    verified: boolean;
    label: string;
    listedAs: string | null;
    change: string;
    /** The email shown for them (pinned, else listed; "" for this account or none): kept with the confirmation. */
    email: string;
  }[];
  /** People the trusted roster lists and the server no longer does (left, declined, deleted): confirmed by user id. */
  missing: { userId: string; role: string; label: string }[];
}

/** The change needs the user to look at the members first (or again: the list changed since). */
export class ReviewNeededError extends Error {
  constructor(public review: ReviewView) {
    super(review.first ? "Check the members before this vault is signed." : "Some people are no longer in this vault. Confirm to continue without them.");
  }
}

/** The vault's state moved between this sync and the request (key, roster, members): sync and try again. */
export class RaceError extends Error {
  constructor() {
    super("This vault changed just now. Try again.");
  }
}

/** What a member list review needs to know about one change. */
export interface ChangeInput {
  vaultId: string;
  answer: MembersAnswer;
  /** The member list the new roster lists (identity, role, listed email). */
  rows: core.RosterMemberInput[];
  /** The key epoch this sync verified (and the requests use). */
  keyEpoch: number;
  /** The member being added or whose role changes (share): may be "added" or "role_changed". */
  target?: string;
  /** The member being removed: expected in `missing`. */
  removed?: string;
  /** Always ask (re-signing shows every member). */
  always?: boolean;
  /** An automatic flow (emergency access): never creates version 1. */
  automatic?: boolean;
  confirmed?: Confirmation;
  what: string;
  /** Names for people the review can't name from the pins. */
  nameOf: NameOf;
}

export interface ChangePlan {
  trusted: string | null;
  review: core.RosterReview;
  rows: core.RosterMemberInput[];
  /** The emails the user confirmed with the review (user id → email). */
  emails: Record<string, string>;
}

/** Rows with the emails the review showed (when confirmed) in place of the members answer's. */
const withShownEmails = (rows: core.RosterMemberInput[], emails: Record<string, string>): core.RosterMemberInput[] =>
  rows.map((r) => (emails[r.user_id] ? { ...r, email: emails[r.user_id] } : r));

/**
 * Plan a signed change (steps 4–6): the vault's state must be the one this sync verified (key epoch, roster version =
 * the trusted one, the same roster), then `rosterReview` of the new member list. Stops on `blocked` (changed keys, an
 * email used by another account, a member's identity differing from the roster), on members the trusted roster
 * doesn't list or lists otherwise, and, unless the user confirmed exactly this list (`confirmed`: the review's digest
 * and every missing user id), whenever there is no trusted roster yet (version 1), people are missing, or `always`.
 */
export function planChange(input: ChangeInput): ChangePlan {
  const { s } = signer();
  const v = s.verified.get(input.vaultId);
  if (!v) throw new Error(VAULT_REFUSED);
  const trusted = v.roster;
  const trustedVersion = trusted ? (rosterNumbers(trusted)?.version ?? -1) : 0;
  // The server's state must be the one verified: same key epoch, same roster (next version = trusted + 1 = server's + 1).
  if (v.epoch !== input.keyEpoch || input.answer.keyEpoch !== input.keyEpoch || input.answer.rosterSeq !== trustedVersion) throw new RaceError();
  try {
    const head = core.rosterHead(input.vaultId, trusted, input.answer.roster);
    if (head.status !== (trusted ? "same" : "unsigned")) throw new RaceError();
  } catch {
    throw new RaceError();
  }
  let review: core.RosterReview;
  try {
    review = core.rosterReview(input.vaultId, trusted, s.me, input.rows, s.pins);
  } catch (e) {
    if (errCode(e) === "roster_unauthorized") throw new Error(`Only the vault's owner can make this change. PassAuth ${input.what}.`);
    throw e;
  }
  const names = (id: string) => {
    const m = review.members.find((x) => x.user_id === id);
    return emailText(m?.pinned_email) || emailText(pinOf(s, id)?.email) || input.nameOf(id);
  };
  if (review.blocked) {
    const changed = review.members.filter((m) => !m.is_self && (m.pin === "changed" || m.pin === "email_conflict"));
    if (changed.length === 1) {
      const m = changed[0];
      const row = input.rows.find((r) => r.user_id === m.user_id)!;
      const info = core.verifyIdentity(identityOf(row));
      throw new KeyChangedError({ identity: identityOf(row), email: names(m.user_id) ?? "", fingerprint: info.fingerprint, hash: info.hash, status: m.pin as KeyChange["status"] });
    }
    const who = review.members.filter((m) => m.pin === "changed" || m.pin === "email_conflict" || m.change === "identity_changed").map((m) => m.user_id);
    throw new Error(membersDifferText(who, names, input.what));
  }
  if (!review.first) {
    const odd = review.members.filter((m) => m.change !== "same" && m.user_id !== input.target).map((m) => m.user_id);
    if (odd.length) throw new Error(membersDifferText(odd, names, input.what));
  }
  const missing = review.missing.filter((m) => m.user_id !== input.removed);
  const others = review.members.some((m) => !m.is_self);
  if (review.first && others && input.automatic) throw new Error(AUTOMATIC_NEEDS_REVIEW);
  const ask = (review.first && others) || missing.length > 0 || !!input.always;
  const ok = !!input.confirmed && input.confirmed.digest === review.digest && missing.every((m) => input.confirmed!.missing.includes(m.user_id));
  if (ask && !ok) throw new ReviewNeededError(reviewView(review, missing, names));
  const emails: Record<string, string> = {};
  if (ok) for (const [user, email] of Object.entries(input.confirmed!.emails ?? {})) if (emailText(email)) emails[user] = emailText(email);
  return { trusted, review, rows: withShownEmails(input.rows, emails), emails };
}

function reviewView(review: core.RosterReview, missing: core.ReviewMissing[], names: (id: string) => string | null): ReviewView {
  return {
    vaultId: review.vault_id,
    digest: review.digest,
    first: review.first,
    version: review.version,
    members: review.members.map((m) => {
      const pinned = emailText(m.pinned_email);
      const listed = emailText(m.listed_email);
      return {
        userId: m.user_id,
        role: m.role,
        fingerprint: m.fingerprint,
        isSelf: m.is_self,
        pin: m.pin,
        verified: m.verified,
        label: m.is_self ? "You" : pinned || listed || "Someone your server lists",
        listedAs: m.is_self ? null : listedAs(pinned, listed),
        change: m.change,
        email: m.is_self ? "" : pinned || listed,
      };
    }),
    missing: missing.map((m) => ({ userId: m.user_id, role: m.role, label: emailText(m.pinned_email) || cleanText(names(m.user_id)) || "Someone who was in this vault" })),
  };
}

/** After the user confirmed (or saw the fingerprint in the share sheet): pin the reviewed people the pins don't know yet. */
export function pinReviewed(plan: ChangePlan) {
  const { s } = signer();
  for (const m of plan.review.members) {
    if (m.is_self || (m.pin !== "new" && m.pin !== "upgraded")) continue;
    const row = plan.rows.find((r) => r.user_id === m.user_id);
    if (!row) continue;
    const email = plan.emails[m.user_id] || emailText(row.email) || emailText(m.listed_email);
    // An upgraded identity keeps its pinned email and "verified" (rule 4).
    if (m.pin === "upgraded") pinUpgraded(s, identityOf(row), email);
    else setPins(s, core.pinSet(s.pins, identityOf(row), email, false, now()) as KeyPins);
  }
}

/** Sign the next roster for `rows` (fetched again right before signing): the core refuses a list other than the reviewed one. */
export function signRosterFor(key: core.VaultKey, vaultId: string, plan: ChangePlan, keyEpoch: number, rows: core.RosterMemberInput[]): string {
  const { identity } = signer();
  try {
    return identity.signRoster(key, vaultId, plan.trusted, keyEpoch, rows, plan.review.digest);
  } catch (e) {
    if (errCode(e) === "review_mismatch") throw new RaceError();
    throw e;
  }
}

/** A signed share of `key` to `recipient` (checked by the plan's review) at `keyEpoch`. */
export function sealAndSign(key: core.VaultKey, vaultId: string, recipient: PublicIdentity, role: string, keyEpoch: number): core.SignedShare {
  const { identity } = signer();
  return identity.sealAndSignShare(key, vaultId, identityOf(recipient), role, keyEpoch);
}

/**
 * A key replacement's keys and roster (step 5): this account's own row wrapped with its account key, every other
 * member's sealed and signed at `newEpoch`, and the next roster listing exactly the plan's members.
 */
export function signedRotationKeys(
  fresh: core.VaultKey,
  ownWrap: string,
  vaultId: string,
  plan: ChangePlan,
  newEpoch: number,
): { keys: { user_id: string; wrapped_key: string; key_kind: "account" | "sealed"; signature?: string }[]; roster: string } {
  const { s, identity } = signer();
  const keys = plan.rows.map((m) => {
    if (m.user_id === s.accountId) return { user_id: m.user_id, wrapped_key: ownWrap, key_kind: "account" as const };
    const share = identity.sealAndSignShare(fresh, vaultId, identityOf(m), m.role, newEpoch);
    return { user_id: m.user_id, wrapped_key: share.sealed_key, key_kind: "sealed" as const, signature: share.signature };
  });
  const roster = signRosterFor(fresh, vaultId, plan, newEpoch, plan.rows);
  return { keys, roster };
}

/** `POST /vaults/{id}/resign` body (step 6): every sealed member's key sealed again and signed, and the next roster. */
export function resignBody(key: core.VaultKey, vaultId: string, members: readonly SignedMemberRow[], plan: ChangePlan, keyEpoch: number) {
  const { s, identity } = signer();
  if (members.some((m) => m.key_kind === null)) throw new Error("The server sent an unexpected response. Try again.");
  const keys = members
    .filter((m) => m.key_kind === "sealed")
    .map((m) => {
      const row = plan.rows.find((r) => r.user_id === m.user_id);
      if (!row) throw new RaceError();
      const recipient = m.user_id === s.accountId ? s.me : identityOf(row);
      const share = identity.sealAndSignShare(key, vaultId, recipient, row.role, keyEpoch);
      return { user_id: m.user_id, wrapped_key: share.sealed_key, signature: share.signature };
    });
  const roster = signRosterFor(key, vaultId, plan, keyEpoch, plan.rows);
  return { key_epoch: keyEpoch, keys, roster };
}

/** A member row as the core takes it for a roster or review. */
export const memberInput = (m: SignedMemberRow, role: string = m.role): core.RosterMemberInput => rosterMember(m, role);

/** Whether a vault needs signing by its owners and admins: no roster yet while shared, or a sealed member's share unsigned. */
export function needsSigning(answer: MembersAnswer): boolean {
  return (answer.rosterSeq === 0 && answer.members.length > 1) || answer.members.some((m) => m.key_kind === "sealed" && m.share === null);
}

/** A name for a user id from the pins (for messages; null when not pinned). */
export function pinnedName(userId: string): string | null {
  return emailText(pinOf(session, userId)?.email) || null;
}

export type { DeviceMemory };
export { NOT_YET_SIGNED };
