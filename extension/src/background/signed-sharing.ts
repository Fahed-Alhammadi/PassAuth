/**
 * Signed sharing, the extension's side (docs/ARCHITECTURE.md "Signed sharing"; servers with the `signed_sharing`
 * feature). Whoever seals a vault key to a member signs the share, and every shared vault has a signed member roster.
 * The server checks shapes but can't vouch for anything, so this browser checks every vault row itself, at every sync
 * (full and delta, live-sync updates too) and offline open, against what the account pinned ("What the apps do",
 * step 1):
 * - the member roster chain from the one this browser trusted last (`rosterHead` → `GET …/rosters` within the caps →
 *   `verifyRosterChain`, ending exactly at the row's roster), its key epoch, that the opened key is the one it commits
 *   to, and that it lists this account with the row's role;
 * - for a vault someone shared (`key_kind = sealed`) with a signature: the signer's identity (`verifyIdentity`,
 *   `pinCheck` against the key pins: a changed key or a known email under a new account stops), the share signature
 *   over this account's identity, role, key epoch and sealed key, and that the roster lists the signer as an owner or
 *   admin with exactly their signing identity;
 * - `pinsAdmit`: the key's epoch and key id against the account's epoch pins, signed history, vaults left, and whether
 *   the account ever accepted the vault (a sealed vault it never accepted waits for the user's consent).
 * A vault that fails is never opened for fill, save, passkeys or display (vault.ts leaves it out of everything) and the
 * popup says why. Pins and the roster memory change only for a row whose every check passed.
 *
 * This file holds the checks (core calls only, no storage and no network but the `fetchRosters` it is given), the
 * device-local memory's shape and merge rule, and the texts; vault.ts runs them and keeps the results.
 */
import type { SyncInvitation, SyncVaultRow } from "@web/lib/types";
import * as core from "../wasm/passauth_core";

// ------------------------------------------------------------------ texts

/** A shared vault that failed a check (the architecture's wording, the same in every app). */
export const REFUSED_TEXT = "PassAuth couldn't verify this shared vault's key, so it isn't used. Ask its owner, or your server's admin.";
/** The server lists a signing identity for this account that isn't its own. */
export const PAUSED_TEXT = "Your server lists a signing key that isn't yours. Sharing is paused on this device.";
/** The server's key pins are older than what this browser saw (it keeps its own copy). */
export const PINS_ROLLBACK_TEXT = "Your server sent an older list of known keys. PassAuth keeps using the newer list this browser has.";
/** A roster couldn't be fetched (offline): the vault waits for the next sync (the same wording as the web vault). */
export const CHECK_LATER_TEXT = "PassAuth couldn't check this shared vault with your server just now, so it isn't used yet. It's checked again at the next sync.";
/** More roster versions to catch up on than one sync checks (1000 versions or 16 MiB). */
export const TOO_MANY_TEXT = "This shared vault has too many changes to check here, so it isn't used. Open it once in the web vault or the desktop app, then sync again.";
/** A `/sync` answer for another account than the one unlocked here. */
export const WRONG_ACCOUNT_TEXT = "Your PassAuth server sent the data of another account. Nothing was changed here. Ask your server's admin.";
/** The account has a signing identity but no key pins anywhere: which shared vaults it accepted is unknown. */
export const MEMORY_MISSING_TEXT = "PassAuth couldn't find your list of known keys on your server, so each shared vault needs your OK again. If you didn't expect this, tell your server's admin.";
/**
 * The account's first signed sync ran on a browser with no offline copy from an earlier session (a new install, an
 * account added again): nothing is grandfathered, so each shared vault from before signing needs the user's OK here
 * (extension re-review M1).
 */
export const NEW_DEVICE_TEXT = "This browser had no earlier copy of your shared vaults, so each one shared before signing needs your OK once. Accept only the ones you expected.";
/** Consent for a key replaced without a signature. */
export const replacedText = (name: string) =>
  `The key of ${name ? `"${name}"` : "a shared vault"} was replaced by an app that doesn't sign yet. Accept it only if someone in this vault just replaced its key.`;
/** A share from before signed sharing. */
export const UNSIGNED_LABEL = "Not yet signed";
export const changedText = (email: string) => `${email || "Someone"}'s keys changed. Compare their fingerprint with them before you continue.`;
export const emailConflictText = (email: string) => `Your server lists a new account for ${email || "someone"}, whose keys you already know under another account.`;
/** "Signed by …" for a vault header; an email that isn't the pinned one is marked as the server's (review L6). */
export const signedByLabel = (email: string, deleted: boolean, pinned = true) =>
  `Signed by ${pinned ? email || "someone" : `${email || "someone"} (as your server lists them)`}${deleted ? " (account deleted)" : ""}`;
/** A sealed vault the account never accepted (planted, or accepted on an app whose memory was lost). */
export const waitingText = (name: string) => `Your server added ${name ? `"${name}"` : "a shared vault"} to your account. Accept it only if you expected it.`;
/** …and it isn't signed: it can't be accepted on a server with signed sharing. */
export const WAITING_UNSIGNED_TEXT = "It isn't signed, so it can't be accepted. Decline it in the web vault, or ask the person who shared it to update PassAuth and share again.";

/** Why a vault was refused, in words (`pinsAdmit` reasons and this file's own codes); the generic text otherwise. */
const REASONS: Record<string, string> = {
  missing_epoch: "Your server didn't say which version of the key it is.",
  paused: PAUSED_TEXT,
  left: "You left this vault; your server lists it again without a newer signed member list.",
  older: "Your server sent an older key than one you already had.",
  conflict: "Your server sent a key that doesn't match the one you already had.",
  downgraded: "This vault was signed before; your server now sends it without its signature or member list.",
  rollback: "Your server sent an older member list than one you already had.",
  roster_forked: "Your server sent a member list that contradicts the one you already had.",
  roster_unauthorized: "The member list was changed by someone not allowed to make that change.",
  bad_signature: "A signature doesn't verify.",
  not_listed: "The signed member list doesn't list you with the role your server says you have.",
  signer_not_manager: "The person who signed the share isn't an owner or admin in the signed member list.",
};

/** The text shown for a refusal with code `why`. */
export const refusedText = (why: string) => {
  const r = REASONS[why];
  return r && r !== PAUSED_TEXT ? `${REFUSED_TEXT} ${r}` : (r ?? REFUSED_TEXT);
};

/**
 * Text from the server made safe to show: one line, control and invisible (format) characters removed, spaces
 * collapsed, at most `max` characters (review M3: names and emails are the server's claims).
 */
export function cleanText(v: unknown, max = 128): string {
  if (typeof v !== "string") return "";
  const one = v
    .replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  const chars = [...one];
  return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : one;
}

/** An email as shown and compared: cleaned, in the core's `normalizeEmail` form (an internationalized domain in punycode). */
export function showEmail(v: unknown): string {
  const c = cleanText(v);
  if (!c) return "";
  try {
    return cleanText(core.normalizeEmail(c));
  } catch {
    return c;
  }
}
const sameEmail = (a: string, b: string) => showEmail(a) === showEmail(b);

// ------------------------------------------------------------------ shapes

/** The signer snapshot a share carries (`share.signer`). */
export interface SignerSnapshot {
  user_id: string;
  email: string;
  name: string;
  public_key: string;
  signing_key: string | null;
  identity_signature: string | null;
  x25519_signature: string | null;
}

/** `share` of a vault row or an invitation: null when the share isn't signed. */
export interface ShareInfo {
  signature: string;
  signer: SignerSnapshot;
  signer_deleted: boolean;
}

/** A vault row with the signed-sharing fields (servers with `signed_sharing`; older ones send none of them). */
export type SignedVaultRow = SyncVaultRow & { share?: unknown; member_roster?: unknown; member_roster_seq?: unknown };

/** An invitation with the signed-sharing fields kept (sync-rules.ts `withSignedFields`). */
export type SignedInvitation = SyncInvitation & { key_epoch?: unknown; share?: unknown; member_roster?: unknown; member_roster_seq?: unknown };

/**
 * Who signed a vault's share, as the popup shows it (the display rule: the email pinned for the person first; what the
 * server lists now only as "listed by your server as …"; "Verified" never next to a server-supplied name or email).
 */
export interface SignerView {
  userId: string;
  /** The pinned email when the person is pinned, else the one the server lists (cleaned). */
  email: string;
  /** Whether `email` is the pinned one (false: only the server's claim, first time seen). */
  pinned: boolean;
  /** What the server lists now when it differs from the pinned email, or the server's name for the person (cleaned). */
  listedAs?: string;
  /** The signer's account was deleted after signing (the share still verifies against the snapshot). */
  deleted: boolean;
  /** Identity fingerprint, computed by the core from the signer's keys. */
  fingerprint: string;
  /** The user marked exactly these keys as compared ("Verified"). */
  verified: boolean;
  /** First time this account sees these keys (pinned now, not compared). */
  firstSeen: boolean;
}

/** A pinned person's keys that changed (or a known email under a new account), and the identity the user may trust. */
export interface ChangedKey {
  kind: "changed" | "email_conflict";
  userId: string;
  /** The email pinned for the person (changed) or the email known under another account (email_conflict). */
  email: string;
  /** The new keys' identity fingerprint: "Trust the new key" pins exactly this identity. */
  fingerprint: string;
  identity: core.PublicIdentity;
  /** The email the server lists with the new keys (cleaned). */
  newEmail: string;
}

/** What a vault's check found. */
export type Trust =
  /** Usable: a personal vault, or a share whose checks passed (`signer` set for a signed share). */
  | { state: "ok"; signer?: SignerView }
  /** A grandfathered share from before signed sharing: usable as before, labelled "Not yet signed". */
  | { state: "unsigned" }
  /**
   * A sealed vault this account never accepted (pinsAdmit `consent`): not used; the popup shows it as waiting for the
   * user, with its name (only the name is decrypted), who signed it and their fingerprint.
   */
  | {
      state: "waiting";
      name: string;
      signer?: SignerView;
      rejoin: boolean;
      /** A key replaced without a signature (an app from before signing) on a vault already accepted. */
      replaced: boolean;
      acceptable: boolean;
      /**
       * What accepting must name ("" when not acceptable): `consentToken` of exactly what was shown (the key id and
       * epoch, the signer's identity hash, the roster hash and the role; review L1), so a row that changed meanwhile
       * is never accepted in its place.
       */
      token: string;
    }
  /** Failed: never used. `why`: the code; `changed`: because a pinned person's keys changed. */
  | { state: "refused"; reason: string; why: string; changed?: ChangedKey };

/**
 * A verdict with what it was made from: `row` = the row it is for (`rowStamp`, what `materialize` compares), `stamp` =
 * the row plus everything else the verdict depends on (`contextStamp`). Kept with the offline copy; an offline open
 * reuses only verdicts whose `stamp` is unchanged.
 */
export interface StoredVerdict {
  stamp: string;
  row: string;
  trust: Trust;
}

/**
 * What this browser remembers per account (device-local, IndexedDB; storage.ts `trustMemory`, keyed by the server's
 * address and the account id the core authenticated): the highest key pins version it opened and its own copy of them
 * (sealed with the account key), the last roster it trusted per vault, and the vaults whose share it has seen signed.
 */
export interface TrustMemory {
  userId: string;
  /** The highest key pins version this browser opened (a lower one from the server is a rollback). */
  pinsSeq: number;
  /** Its copy of the key pins, sealed with the account key as version `pinsSeq` (null: none yet). */
  pinsSealed: string | null;
  /** The copy has changes the server doesn't have yet (written at the next sync). */
  pinsDirty: boolean;
  /** Per vault id, the roster text this browser trusted last. */
  rosters: Record<string, string>;
  /** Vault ids whose share this browser has seen signed. */
  signed: string[];
  /** Trust memory missing (identity without key pins at the first signed sync): the shared vaults then, while they wait. */
  missing?: string[];
  /** Why `missing` is set: "device" = the first signed sync on a browser with no earlier offline copy (M1); absent = lost key pins. */
  missingWhy?: "device";
  /**
   * The identity hash of a signing identity this browser made and is uploading (`PUT /account/identity`), kept until
   * the server lists an identity: if that one opens to this hash, this browser created it even though the answer to the
   * upload was lost (cross-client review B; the server can't make a record that opens under the account key).
   */
  pendingIdentity?: string;
}

export const emptyMemory = (userId: string): TrustMemory => ({ userId, pinsSeq: 0, pinsSealed: null, pinsDirty: false, rosters: {}, signed: [] });

const whole = (v: unknown): number | null => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);

/** A memory record as stored for `userId`, or null when it isn't one (or another account's: never reused). */
export function readMemory(v: unknown, userId: string): TrustMemory | null {
  const m = v as Partial<TrustMemory> | null;
  if (!m || typeof m !== "object" || m.userId !== userId) return null;
  const rosters: Record<string, string> = {};
  if (m.rosters && typeof m.rosters === "object") for (const [id, r] of Object.entries(m.rosters)) if (typeof r === "string") rosters[id] = r;
  return {
    userId,
    pinsSeq: whole(m.pinsSeq) ?? 0,
    pinsSealed: typeof m.pinsSealed === "string" ? m.pinsSealed : null,
    pinsDirty: m.pinsDirty === true,
    rosters,
    signed: Array.isArray(m.signed) ? m.signed.filter((s): s is string => typeof s === "string") : [],
    ...(Array.isArray(m.missing) ? { missing: m.missing.filter((s): s is string => typeof s === "string") } : {}),
    ...(m.missingWhy === "device" ? { missingWhy: "device" as const } : {}),
    ...(typeof m.pendingIdentity === "string" ? { pendingIdentity: m.pendingIdentity } : {}),
  };
}

/** Whether the browser has seen anything signed for the account (then checks run even if the server stops listing `signed_sharing`). */
export const remembersSigned = (m: TrustMemory | null) => !!m && (m.pinsSeq > 0 || m.pinsSealed !== null || m.signed.length > 0 || Object.keys(m.rosters).length > 0);

/** A roster's version, read after the core accepted it (null: not a roster). */
export function rosterVersion(json: string): number | null {
  try {
    return whole((JSON.parse(json) as { version?: unknown }).version);
  } catch {
    return null;
  }
}

/** A roster's `key_epoch`, read after the core accepted it. */
function rosterEpoch(json: string): number | null {
  try {
    return whole((JSON.parse(json) as { key_epoch?: unknown }).key_epoch);
  } catch {
    return null;
  }
}

/**
 * Two memories of the same account merged (the merge rule: never overwrite): the higher key pins version with its
 * sealed copy (`mergePins` combines both copies when the lower one has unsent changes; without it the lower one's
 * changes wait to be made again), the higher trusted roster per vault, and the union of the "seen signed" marks.
 * `basis`: the sealed copy `ours` was made from. A stored copy with unsent changes that isn't it was written meanwhile
 * (a "Trust the new key" during a sync, review L7): it is merged in even at the same or a lower version, never dropped.
 */
export function mergeMemory(stored: TrustMemory | null, ours: TrustMemory, mergePins?: (higher: TrustMemory, lower: TrustMemory) => TrustMemory, basis?: string | null): TrustMemory {
  if (!stored || stored.userId !== ours.userId) return ours;
  const rosters: Record<string, string> = { ...stored.rosters };
  for (const [id, r] of Object.entries(ours.rosters)) {
    const theirs = rosters[id];
    if (theirs === undefined || (rosterVersion(r) ?? -1) >= (rosterVersion(theirs) ?? -1)) rosters[id] = r;
  }
  const signed = [...new Set([...stored.signed, ...ours.signed])];
  let pins: TrustMemory = ours;
  const storedHigher = stored.pinsSeq > ours.pinsSeq || (stored.pinsSealed !== null && ours.pinsSealed === null);
  const editedMeanwhile = basis !== undefined && stored.pinsDirty && stored.pinsSealed !== null && ours.pinsSealed !== null && stored.pinsSealed !== basis && stored.pinsSealed !== ours.pinsSealed;
  if (editedMeanwhile && mergePins) pins = storedHigher ? mergePins(stored, ours) : mergePins(ours, stored);
  else if (storedHigher) pins = ours.pinsDirty && ours.pinsSealed !== null && mergePins ? mergePins(stored, ours) : stored;
  // `missing` is this browser's own state: ours (the latest check's).
  return {
    userId: ours.userId,
    pinsSeq: pins.pinsSeq,
    pinsSealed: pins.pinsSealed,
    pinsDirty: pins.pinsDirty,
    rosters,
    signed,
    ...(ours.missing ? { missing: ours.missing, ...(ours.missingWhy ? { missingWhy: ours.missingWhy } : {}) } : {}),
    // This browser's own state too: ours (`ensureIdentity` keeps it in both while an upload is on its way).
    ...(ours.pendingIdentity ? { pendingIdentity: ours.pendingIdentity } : {}),
  };
}

const isStr = (v: unknown): v is string => typeof v === "string";
const optStr = (v: unknown): v is string | null | undefined => v === undefined || v === null || typeof v === "string";

/** A signer snapshot from the server, or null when it isn't one. */
export function readSigner(v: unknown): SignerSnapshot | null {
  const s = v as Record<string, unknown> | null;
  if (!s || typeof s !== "object" || !isStr(s.user_id) || !s.user_id || !isStr(s.public_key)) return null;
  if (!optStr(s.signing_key) || !optStr(s.identity_signature) || !optStr(s.x25519_signature)) return null;
  return {
    user_id: s.user_id,
    email: isStr(s.email) ? s.email : "",
    name: isStr(s.name) ? s.name : "",
    public_key: s.public_key,
    signing_key: s.signing_key ?? null,
    identity_signature: s.identity_signature ?? null,
    x25519_signature: s.x25519_signature ?? null,
  };
}

/** A row's or invitation's `share`: null when unsigned; "malformed" when it is something else than a share. */
export function readShare(v: unknown): ShareInfo | null | "malformed" {
  if (v === null || v === undefined) return null;
  const s = v as Record<string, unknown>;
  if (typeof s !== "object" || !isStr(s.signature) || !s.signature) return "malformed";
  const signer = readSigner(s.signer);
  if (!signer) return "malformed";
  return { signature: s.signature, signer, signer_deleted: s.signer_deleted === true };
}

/** The identity the core verifies: only the key fields of a snapshot. */
export const publicOf = (s: SignerSnapshot): core.PublicIdentity => ({
  user_id: s.user_id,
  public_key: s.public_key,
  signing_key: s.signing_key,
  identity_signature: s.identity_signature,
  x25519_signature: s.x25519_signature,
});

/** What the row is (the fields a verdict is about): `materialize` opens a vault only with a verdict for this row. */
export function rowStamp(row: SignedVaultRow): string {
  return JSON.stringify([row.id, row.key_kind, row.wrapped_key, row.key_epoch ?? null, row.role, row.meta ?? null, row.share ?? null, row.member_roster ?? null]);
}

/** Everything a verdict depends on besides the row (see `contextStamp`). */
export interface StampContext {
  /** `pinsDigest` of the key pins the check ran with. */
  pins: string;
  /** The roster this browser trusted for the vault. */
  remembered: string | null;
  /** Seen signed here. */
  seenSigned: boolean;
  paused: boolean;
  /** This account's identity hash (signing, or legacy before it has one). */
  me: string;
}

/** SHA-256 (base64url) of a text. */
async function sha256(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let s = "";
  for (const b of d) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A digest of the key pins (without `version`, which sealing sets): any pin, epoch, tombstone or grandfathered change changes it. */
export const pinsDigest = (pins: core.KeyPins | null) => sha256(JSON.stringify(pins ? { ...pins, version: 0 } : null));

/**
 * The version of these checks. Part of every stamp (review L2): a verdict kept by an older version of the extension is
 * checked again rather than reused offline. Raise it whenever a check changes what it decides.
 */
export const CHECKS_VERSION = 4;

/** The stamp of a verdict: the row and everything else it depends on (pins, roster memory, paused, own identity, the checks' version). */
export const contextStamp = (row: SignedVaultRow, c: StampContext, version = CHECKS_VERSION) => sha256(JSON.stringify([version, rowStamp(row), c.pins, c.remembered, c.seenSigned, c.paused, c.me]));

/**
 * What accepting a waiting vault names (review L1): a digest of exactly what the popup showed: the vault, its role, key
 * id and epoch, the signer's identity hash (null: unsigned), the trusted roster's hash (null: none) and the kind of
 * consent. A row that changed in any of these since gets another token, so it is never accepted in the shown one's place.
 */
export const consentToken = (c: { vaultId: string; role: string; keyId: string; epoch: number; signer: string | null; roster: string | null; replaced: boolean; rejoin: boolean }) =>
  sha256(JSON.stringify(["passauth/consent/v1", c.vaultId, c.role, c.keyId, c.epoch, c.signer, c.roster, c.replaced, c.rejoin]));

/** The error code the core threw (its message), for logs. */
export const coreCode = (e: unknown) => (e instanceof Error ? e.message : String(e));

const pinOf = (pins: core.KeyPins | null, userId: string) => pins?.pins.find((p) => p.user_id === userId);

/** Roster fetching gave up: more versions or text than one sync checks. */
export class TooManyRosters extends Error {
  constructor() {
    super("too_large");
  }
}

/** Per sync and vault: at most this many roster versions (10 pages of 100), and this much roster text. */
export const MAX_ROSTERS = 1000;
export const MAX_ROSTER_BYTES = 16 * 1024 * 1024;
const MAX_PAGES = 10;

/**
 * Every roster after version `after`, oldest first, from `page(after)` (`GET /vaults/{id}/rosters?after=`), within the
 * caps (`TooManyRosters` beyond them: the vault is refused rather than a partial chain trusted).
 */
export async function collectRosters(after: number, page: (after: number) => Promise<{ rosters: string[]; more: boolean }>): Promise<string[]> {
  const out: string[] = [];
  let bytes = 0;
  for (let n = 0; n < MAX_PAGES; n++) {
    const r = await page(after + out.length);
    for (const s of r.rosters) {
      bytes += s.length;
      out.push(s);
    }
    if (out.length > MAX_ROSTERS || bytes > MAX_ROSTER_BYTES) throw new TooManyRosters();
    if (!r.more || r.rosters.length === 0) return out;
  }
  throw new TooManyRosters();
}

/** How a signer's identity shows (the display rule), from its pin check. */
function signerView(share: ShareInfo, info: core.IdentityInfo, status: string, pinned: core.KeyPin | undefined): SignerView {
  const listed = showEmail(share.signer.email);
  const name = cleanText(share.signer.name);
  const pinnedEmail = status === "match" || status === "upgraded" ? showEmail(pinned?.email) : "";
  const email = pinnedEmail || listed;
  const listedAs = pinnedEmail && listed && !sameEmail(pinnedEmail, listed) ? listed : name && name !== email ? name : undefined;
  return {
    userId: share.signer.user_id,
    email,
    pinned: !!pinnedEmail,
    ...(listedAs ? { listedAs } : {}),
    deleted: share.signer_deleted,
    fingerprint: info.fingerprint,
    verified: status === "match" && pinned?.verified === true,
    firstSeen: status !== "match",
  };
}

// ------------------------------------------------------------------ one vault

/**
 * The role a roster the core already verified gives the member `userId` listed with the identity hash `identity` (the
 * account's remembered own identity); undefined when it doesn't list them so.
 */
function ownRosterRole(roster: string, userId: string, identity: string | null | undefined): string | undefined {
  if (!identity) return undefined;
  try {
    const members = (JSON.parse(roster) as { members?: unknown }).members;
    if (!Array.isArray(members)) return undefined;
    const m = members.find((x) => !!x && typeof x === "object" && (x as { user_id?: unknown }).user_id === userId && (x as { identity?: unknown }).identity === identity) as
      | { role?: unknown }
      | undefined;
    return typeof m?.role === "string" ? m.role : undefined;
  } catch {
    return undefined;
  }
}

/** The verdict for a row that isn't opened at all: no key epoch, or a shared vault while sharing is paused. */
export const refusedUnopened = (why: "missing_epoch" | "paused"): Trust => ({ state: "refused", reason: why === "paused" ? PAUSED_TEXT : refusedText(why), why });

export interface VaultCheckInput {
  row: SignedVaultRow;
  /** The row's key, opened by the caller with the row's key epoch (and freed by it). */
  key: core.VaultKey;
  /** This account's identity: its signing identity's, or its legacy one before it has one. */
  me: core.PublicIdentity;
  /** The account's key pins as this browser has them (null: none yet). */
  pins: core.KeyPins | null;
  /** The roster text this browser trusted last for the vault. */
  remembered: string | null;
  /** This browser has seen the vault's share signed before. */
  seenSigned: boolean;
  /** Sharing is paused here (the server's identity for this account isn't its own): no sealed row is used. */
  paused: boolean;
  /** Every roster of the vault after version `after`, oldest first, within the caps (`collectRosters`). */
  fetchRosters: (after: number) => Promise<string[]>;
  /** Unix seconds, for new pins. */
  now: number;
  /** The user accepted this vault, waiting for consent, with this token (`consentToken` of what the popup showed). */
  accept?: string;
  /** This account's trust memory is missing (identity without key pins): unsigned vaults it has may be accepted here. */
  memoryMissing?: boolean;
}

export interface VaultCheck {
  trust: Trust;
  /** The key pins after this vault (a raised epoch pin, a new signer pin): the input's unless every check passed. */
  pins: core.KeyPins | null;
  /** The roster to remember as trusted for the vault (only after every check passed; else null). */
  roster: string | null;
  /** The share was signed and passed (remember it, so a later unsigned row is refused). */
  signed: boolean;
}

/**
 * Check one vault row (docs/ARCHITECTURE.md "What the apps do", step 1). Never throws for anything the server sent: a
 * failure is a refused verdict. `fetchRosters` failing (offline) is a refusal until the next sync.
 */
export async function checkVault(input: VaultCheckInput): Promise<VaultCheck> {
  const { row, key, me } = input;
  const refuse = (why: string, reason = refusedText(why), changed?: ChangedKey): VaultCheck => ({
    trust: { state: "refused", reason, why, ...(changed ? { changed } : {}) },
    pins: input.pins,
    roster: null,
    signed: false,
  });
  try {
    const epoch = whole(row.key_epoch);
    const share = readShare(row.share);
    const latest = isStr(row.member_roster) ? row.member_roster : null;
    if (share === "malformed") return refuse("malformed share");
    if (row.member_roster !== undefined && row.member_roster !== null && latest === null) return refuse("malformed roster");
    if (row.key_kind !== "sealed" && row.key_kind !== "account") return refuse("malformed key kind");
    const sealed = row.key_kind === "sealed";
    // Signed data always names its key's epoch; without one nothing can be compared (pinsAdmit says the same).
    if (epoch === null) return refuse("missing_epoch");
    if (sealed && input.paused) return refuse("paused", PAUSED_TEXT);

    // (b) The member roster chain from the one trusted last, ending exactly at the row's.
    let trusted: string | null = null;
    const head = core.rosterHead(row.id, input.remembered, latest);
    if (head.status === "same") trusted = input.remembered;
    else if (head.status === "fetch" && latest !== null) {
      let newer: string[];
      try {
        newer = await input.fetchRosters(head.after);
      } catch (e) {
        if (e instanceof TooManyRosters) return refuse("too_large", TOO_MANY_TEXT);
        return refuse(`rosters not fetched: ${coreCode(e)}`, CHECK_LATER_TEXT);
      }
      // Up to the version the row names (a newer one may have been written since): it must be among them.
      const at = newer.indexOf(latest);
      if (at < 0) return refuse("roster not served");
      trusted = core.verifyRosterChain(row.id, input.remembered, newer.slice(0, at + 1), latest);
    }
    const version = trusted !== null ? rosterVersion(trusted) : null;
    if (trusted !== null) {
      if (version === null || rosterEpoch(trusted) !== epoch) return refuse("roster names another key epoch");
      if (!key.matchesRoster(row.id, trusted)) return refuse("key doesn't match the roster");
      // The roster lists me with the row's role (review L5/L6): the server can't raise or invent a membership. While
      // sharing is paused `me` is the legacy identity; an own (account-wrapped) vault's roster lists the full one the
      // account remembers (`own_identity`, review L8).
      const role = core.rosterMemberRole(trusted, me) ?? (!sealed && input.paused ? ownRosterRole(trusted, me.user_id, input.pins?.own_identity) : undefined);
      if ((role ?? null) !== row.role) return refuse("not_listed");
    }

    // (c) The share of a vault someone shared.
    let view: SignerView | undefined;
    let signerHash: string | null = null;
    let signerPin: { identity: core.PublicIdentity; email: string } | null = null;
    const signedShare = sealed && share !== null;
    if (sealed && share) {
      const signer = publicOf(share.signer);
      const info = core.verifyIdentity(signer);
      const pinned = pinOf(input.pins, signer.user_id);
      const status = core.pinCheck(input.pins, signer, share.signer.email);
      if (status === "changed" || status === "email_conflict") {
        // changed: the email pinned for the person; email_conflict: the email as pinned for the account it is known under.
        const known = status === "changed" ? showEmail(pinned?.email) : showEmail(input.pins?.pins.find((p) => sameEmail(p.email, share.signer.email))?.email ?? share.signer.email);
        const changed: ChangedKey = { kind: status, userId: signer.user_id, email: known, fingerprint: info.fingerprint, identity: signer, newEmail: showEmail(share.signer.email) };
        return refuse(status, status === "changed" ? changedText(known) : emailConflictText(known), changed);
      }
      core.verifyShare(row.id, me, row.role, epoch, row.wrapped_key, signer, share.signature);
      // A signed share always comes with a roster, which must list the signer as an owner or admin.
      if (trusted === null) return refuse("downgraded");
      const role = core.rosterSignerRole(trusted, signer);
      if (role !== "owner" && role !== "admin") return refuse("signer_not_manager");
      view = signerView(share, info, status, pinned);
      signerHash = info.hash;
      if (status === "new" || status === "upgraded") signerPin = { identity: signer, email: status === "upgraded" ? showEmail(pinned?.email) || view.email : view.email };
    } else if (sealed && input.seenSigned) {
      // Seen signed in this browser: an unsigned share now is a rollback (pinsAdmit catches it from the account's pins).
      return refuse("downgraded");
    }

    // (d) Admission: epochs, key ids, signed history, the highest trusted roster, vaults left, consent. `pinsObserve`
    // applies what the verdict says to pin (`pin`), with the roster's hash; its pins are kept only for an ok row.
    const current = key.epochPin(row.id, epoch);
    const observation: core.VaultObservation = {
      vault_id: row.id,
      key_kind: row.key_kind,
      key: current,
      roster_version: version,
      roster_hash: trusted !== null ? core.rosterHash(trusted) : null,
      signed_share: signedShare,
      paused: input.paused,
    };
    const observed = core.pinsObserve(input.pins, observation);
    const adm = observed.admission;
    if (adm.status === "refused") return refuse(adm.reason, adm.reason === "paused" ? PAUSED_TEXT : refusedText(adm.reason));
    const withSigner = (pins: core.KeyPins) => (signerPin ? core.pinSet(pins, signerPin.identity, signerPin.email, false, input.now) : pins);
    if (adm.status === "consent") {
      // What the user may accept here: a signed share (from the signer shown), a key replaced by an app that doesn't sign
      // yet, or, while this account's trust memory is missing, an unsigned vault it had (both: the key shown).
      const unsignedOk = !signedShare && (adm.replaced || input.memoryMissing === true);
      const token =
        (signedShare && view) || unsignedOk
          ? await consentToken({
              vaultId: row.id,
              role: row.role,
              keyId: current.key_id,
              epoch,
              signer: signedShare ? signerHash : null,
              roster: trusted !== null ? core.rosterHash(trusted) : null,
              replaced: adm.replaced,
              rejoin: adm.rejoin,
            })
          : "";
      if (token && input.accept !== undefined && input.accept === token) {
        let pins: core.KeyPins;
        try {
          // Accepting = pinning its key (clears a tombstone when the re-share qualifies), then what the row shows
          // (roster version and hash), its signer and its roster.
          const accepted = core.pinsSetEpoch(input.pins, row.id, current, signedShare ? version : null);
          const again = core.pinsObserve(accepted, observation);
          if (again.admission.status !== "ok") return refuse(again.admission.status === "refused" ? again.admission.reason : "consent");
          pins = withSigner(again.pins);
        } catch (e) {
          return refuse(coreCode(e) === "rollback" ? "left" : coreCode(e));
        }
        const trust: Trust = signedShare && view ? { state: "ok", signer: view } : { state: "unsigned" };
        return { trust, pins, roster: trusted, signed: signedShare };
      }
      let name = "";
      try {
        const meta = typeof row.meta === "string" ? (key.decryptMeta(row.id, row.meta) as { name?: unknown }) : null;
        name = cleanText(meta?.name);
      } catch {
        name = "";
      }
      return {
        trust: { state: "waiting", name, ...(view ? { signer: view } : {}), rejoin: adm.rejoin, replaced: adm.replaced, acceptable: !!token, token },
        pins: input.pins,
        roster: null,
        signed: false,
      };
    }
    // ok: every check passed; only now are the key's epoch (what `pin` says), a new signer and the roster remembered.
    const pins = withSigner(observed.pins);
    const trust: Trust = adm.trust === "unsigned" ? { state: "unsigned" } : view ? { state: "ok", signer: view } : { state: "ok" };
    return { trust, pins, roster: trusted, signed: signedShare };
  } catch (e) {
    return refuse(coreCode(e));
  }
}

// ------------------------------------------------------------------ invitations

/** What the popup says about a waiting invitation. */
export interface InvitationCheck {
  vaultId: string;
  /** "unsigned": can't be accepted on a server with signed sharing; "refused": a signature or key check failed; "changed": the sharer's pinned keys changed. */
  state: "ok" | "unsigned" | "refused" | "changed";
  /**
   * Who shared it, as far as this browser knows: the email pinned for the verified signer (the display rule), else ""
   * (then only `listedAs` names them).
   */
  from: string;
  /** Who the server says it is from (the signer snapshot's email, else `invited_by`), cleaned: "listed by your server as …". */
  listedAs?: string;
}

/**
 * Check a waiting invitation as far as the extension can (it doesn't accept invitations; the other apps do, after the
 * full check with the roster): its share is signed, by an identity whose pin didn't change, over this account.
 * Nothing is pinned here (an invitation's signer is pinned only when the user accepts it). The server's `invited_by`
 * is never more than "listed by your server as …"; only a verified signer's pinned email names the sharer.
 */
export function checkInvitation(inv: SignedInvitation, me: core.PublicIdentity, pins: core.KeyPins | null, paused: boolean): InvitationCheck {
  const by = inv.invited_by;
  const claimed = by ? showEmail(by.email) || cleanText(by.name) : "";
  const out = (state: InvitationCheck["state"], from: string, listed: string): InvitationCheck => ({
    vaultId: inv.vault_id,
    state,
    from,
    ...(listed && !sameEmail(listed, from) ? { listedAs: listed } : {}),
  });
  const share = readShare(inv.share);
  if (share === null) return out("unsigned", "", claimed);
  if (share === "malformed") return out("refused", "", claimed);
  const listed = showEmail(share.signer.email) || claimed;
  if (paused) return out("refused", "", listed);
  try {
    const signer = publicOf(share.signer);
    core.verifyIdentity(signer);
    const status = core.pinCheck(pins, signer, share.signer.email);
    const pinnedEmail = showEmail(pinOf(pins, signer.user_id)?.email);
    // The person whose pinned keys changed is named by the email pinned with the old keys.
    if (status === "changed") return out("changed", pinnedEmail, listed);
    if (status === "email_conflict") return out("refused", "", listed);
    const epoch = whole(inv.key_epoch);
    if (epoch === null) return out("refused", "", listed);
    core.verifyShare(inv.vault_id, me, inv.role, epoch, inv.wrapped_key, signer, share.signature);
    return out("ok", status === "match" || status === "upgraded" ? pinnedEmail : "", listed);
  } catch {
    return out("refused", "", listed);
  }
}

// ------------------------------------------------------------------ the popup

/** The popup's sentence for an invitation that can't be accepted; null for a signed one that checked out. */
export function invitationText(c: InvitationCheck): string | null {
  // The pinned email first; what the server lists only as its claim (the display rule).
  const listed = c.listedAs ? `listed by your server as from ${c.listedAs}` : "";
  const subject = c.from ? `The invitation from ${c.from}${listed ? ` (${listed})` : ""}` : listed ? `An invitation ${listed}` : "An invitation";
  const ask = c.from || "the person who shared it";
  if (c.state === "unsigned") return `${subject} isn't signed. Ask ${ask} to update PassAuth and share again.`;
  if (c.state === "changed") return changedText(c.from);
  if (c.state === "refused")
    return `PassAuth couldn't verify ${subject.charAt(0).toLowerCase()}${subject.slice(1)}. Don't accept it; ask ${c.from ? "them" : "the person who shared it"}, or your server's admin.`;
  return null;
}
