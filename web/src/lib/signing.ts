/**
 * Signed sharing, the pure part (docs/ARCHITECTURE.md "Signed sharing"): reading the server's signing fields (every value
 * that reaches the core is checked to be a string first, every name or email cleaned), this device's trust memory (per
 * server and account: each vault's last trusted member roster, vaults seen signed, the account's own identity, and the
 * local copy of the key pins; writes merge, never overwrite), and the app's wording. No WASM, network or React here;
 * `signed-sharing.ts` does the checks with the core.
 *
 * Unit-tested in `signing.test.ts`.
 */
import { oneLine } from "./text";
import type { MemberRow, Role } from "./types";

/** A user's public identity as the core takes it (`signing_key`/`identity_signature`/`x25519_signature` null: legacy). */
export interface PublicIdentity {
  user_id: string;
  public_key: string;
  signing_key: string | null;
  identity_signature: string | null;
  x25519_signature: string | null;
}

/** `PUT /account/identity` body and `/sync` `user.identity`. */
export interface IdentityRecord {
  signing_key: string;
  identity_signature: string;
  x25519_signature: string;
  wrapped_signing_key: string;
}

/** Who signed a share, as the server kept them when it was signed (cleaned; their email and name may have changed since). */
export interface ShareSigner extends PublicIdentity {
  email: string;
  name: string;
}

/** A membership's share signature (`share` of vault rows, invitations and member rows). */
export interface ShareInfo {
  signature: string;
  signer: ShareSigner;
  /** The signer's account was deleted since (the share still verifies against the snapshot). */
  signerDeleted: boolean;
}

/** `readShare`'s answer for a `share` that is there but isn't usable: never treated as "not signed" (that would be a downgrade). */
export const MALFORMED = "malformed" as const;

/** Longest name or email shown (characters). */
export const NAME_MAX = 128;

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const filled = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const absent = (v: unknown) => v === undefined || v === null;
const wholeNumber = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER;

/** A name or email from the server (or anyone else) as shown and pinned: one line, no invisible characters, at most 128 characters. */
export const cleanText = (v: unknown): string => oneLine(v, NAME_MAX);

/**
 * A public identity from a server object (a lookup answer, a member row, a share's signer): user id and X25519 key as
 * non-empty strings, and the signing key with both its signatures all three strings or all three missing (legacy).
 * Null otherwise. `idField` names the user id's field (`invited_by` uses `id`).
 */
export function readIdentity(v: unknown, idField: "user_id" | "id" = "user_id"): PublicIdentity | null {
  if (!isRecord(v)) return null;
  const userId = v[idField] ?? v.user_id;
  if (!filled(userId) || !filled(v.public_key)) return null;
  const parts = [v.signing_key, v.identity_signature, v.x25519_signature];
  if (parts.every(filled)) {
    return { user_id: userId, public_key: v.public_key, signing_key: parts[0] as string, identity_signature: parts[1] as string, x25519_signature: parts[2] as string };
  }
  // Some without the others can't be checked: refuse rather than read it as a legacy identity (a downgrade).
  if (!parts.every(absent)) return null;
  return { user_id: userId, public_key: v.public_key, signing_key: null, identity_signature: null, x25519_signature: null };
}

/** Only the five fields the core reads (a server object may carry more). */
export const identityOf = (i: {
  user_id: string;
  public_key: string;
  signing_key?: string | null;
  identity_signature?: string | null;
  x25519_signature?: string | null;
}): PublicIdentity => ({
  user_id: i.user_id,
  public_key: i.public_key,
  signing_key: i.signing_key ?? null,
  identity_signature: i.identity_signature ?? null,
  x25519_signature: i.x25519_signature ?? null,
});

/** `/sync` `user.identity`: the record when every field is a non-empty string, null when there is none, MALFORMED otherwise. */
export function readIdentityRecord(v: unknown): IdentityRecord | null | typeof MALFORMED {
  if (v === null || v === undefined) return null;
  if (!isRecord(v) || !filled(v.signing_key) || !filled(v.identity_signature) || !filled(v.x25519_signature) || !filled(v.wrapped_signing_key))
    return MALFORMED;
  return { signing_key: v.signing_key, identity_signature: v.identity_signature, x25519_signature: v.x25519_signature, wrapped_signing_key: v.wrapped_signing_key };
}

/** A `share` field: null when the share isn't signed (or the field is missing: servers from before), MALFORMED when unusable. */
export function readShare(v: unknown): ShareInfo | null | typeof MALFORMED {
  if (v === null || v === undefined) return null;
  if (!isRecord(v) || !filled(v.signature)) return MALFORMED;
  const signer = readIdentity(v.signer);
  // A share is signed by a signing identity: a legacy "signer" can't have signed anything.
  if (!signer || !signer.signing_key || !isRecord(v.signer)) return MALFORMED;
  const s = v.signer;
  return {
    signature: v.signature,
    signer: { ...signer, email: cleanText(s.email), name: cleanText(s.name) },
    signerDeleted: v.signer_deleted === true,
  };
}

/** A member roster field (`member_roster`): its JSON text, null for none, MALFORMED for anything else. */
export function readRosterText(v: unknown): string | null | typeof MALFORMED {
  if (v === null || v === undefined) return null;
  return filled(v) ? v : MALFORMED;
}

/** A vault member with what signed sharing needs (`GET /vaults/{id}/members`); `email` and `name` cleaned. */
export interface SignedMemberRow extends MemberRow {
  signing_key: string | null;
  identity_signature: string | null;
  x25519_signature: string | null;
  key_kind: "account" | "sealed" | null;
  share: ShareInfo | null | typeof MALFORMED;
}

/** `GET /vaults/{id}/members` with the vault's key epoch and member roster (servers with `signed_sharing`). */
export interface MembersAnswer {
  members: SignedMemberRow[];
  /** Undefined from servers without key epochs. */
  keyEpoch: number | undefined;
  /** The latest member roster's text; null when the vault has none. */
  roster: string | null;
  /** Its version (0: none). */
  rosterSeq: number;
}

/**
 * The members list: every row needs its user id, email, name, role and X25519 key as strings and a usable identity, so
 * nobody is skipped and nothing unusable reaches the core. Null when any row doesn't, a user is listed twice, or the
 * roster fields are wrong.
 */
export function readMembersAnswer(value: unknown): MembersAnswer | null {
  if (!isRecord(value) || !Array.isArray(value.members)) return null;
  const members: SignedMemberRow[] = [];
  const seen = new Set<string>();
  for (const m of value.members) {
    if (!isRecord(m) || !filled(m.user_id) || typeof m.email !== "string" || typeof m.name !== "string" || !filled(m.role)) return null;
    const id = readIdentity(m);
    if (!id || seen.has(id.user_id)) return null;
    seen.add(id.user_id);
    members.push({
      ...id,
      email: cleanText(m.email),
      name: cleanText(m.name),
      role: m.role as Role,
      key_kind: m.key_kind === "account" || m.key_kind === "sealed" ? m.key_kind : null,
      share: readShare(m.share),
      ...(m.status === "active" || m.status === "invited" ? { status: m.status } : {}),
      ...(typeof m.invited_by === "string" || m.invited_by === null ? { invited_by: m.invited_by } : {}),
      ...(typeof m.invited_at === "number" && Number.isFinite(m.invited_at) ? { invited_at: m.invited_at } : {}),
    });
  }
  const roster = readRosterText(value.member_roster);
  if (roster === MALFORMED) return null;
  const seq = value.member_roster_seq;
  if (seq !== undefined && !wholeNumber(seq)) return null;
  const epoch = value.key_epoch;
  if (epoch !== undefined && !wholeNumber(epoch)) return null;
  return { members, keyEpoch: epoch, roster, rosterSeq: seq ?? 0 };
}

/** A member row as the core takes it for a roster or review (`RosterMemberInput`): identity, role and the listed email. */
export const rosterMember = (m: PublicIdentity & { email?: string }, role: string) => ({ ...identityOf(m), role, email: m.email ? cleanText(m.email) : null });

/** One page of `GET /vaults/{id}/rosters?after=`: the rosters' texts, oldest first, and whether there are more. */
export function readRostersPage(value: unknown): { rosters: string[]; more: boolean } | null {
  if (!isRecord(value) || !Array.isArray(value.rosters) || !value.rosters.every(filled)) return null;
  return { rosters: value.rosters as string[], more: value.more === true };
}

/** At most this many roster versions and this much roster text per vault and sync; beyond, the vault is refused. */
export const ROSTER_VERSIONS_MAX = 1000;
export const ROSTER_PAGES_MAX = 10;
export const ROSTER_BYTES_MAX = 16 * 1024 * 1024;

/**
 * Two numbers out of a roster text the core already verified (`verifyRosterChain`): its version and key epoch. Read
 * only from text the core accepted, never to decide whether a roster is genuine. Null when they aren't whole numbers.
 */
export function rosterNumbers(json: string): { version: number; keyEpoch: number } | null {
  try {
    const r = JSON.parse(json) as { version?: unknown; key_epoch?: unknown };
    return wholeNumber(r.version) && wholeNumber(r.key_epoch) ? { version: r.version, keyEpoch: r.key_epoch } : null;
  } catch {
    return null;
  }
}

/** The user ids a verified roster lists (for "does it list anyone else"). */
export function rosterUserIds(json: string): string[] {
  try {
    const r = JSON.parse(json) as { members?: unknown };
    return Array.isArray(r.members) ? r.members.map((m) => (isRecord(m) && typeof m.user_id === "string" ? m.user_id : "")).filter(Boolean) : [];
  } catch {
    return [];
  }
}

// ------------------------------------------------------------ device memory

/**
 * What this device remembers, per server and account (`scope`, in local storage): whether signed sharing was ever on
 * (checks then stay on), the account's own identity hash, and per vault the last member roster it trusted and whether
 * it was seen signed. Nothing ever goes back: a server that later shows an older roster, none, or an unsigned share for
 * a vault seen signed is refused.
 */
export interface VaultMemory {
  roster?: string;
  signed?: boolean;
}

export interface DeviceMemory {
  /** Signed sharing was on for this account here once: the checks stay on. Written only after the server showed it signs. */
  on: boolean;
  /** The account's own identity hash, as first seen here. */
  own: string | null;
  vaults: Record<string, VaultMemory>;
  /**
   * Identity hashes this device generated before `PUT /account/identity` (newest last, at most 4): a listed record that
   * opens to one of them was made here even when the answer to the `PUT` was lost (review L-A).
   */
  generated: string[];
  /**
   * Shared vaults that, at the account's first signed sync here, were waiting with no trust memory to tell (key pins
   * missing, or no earlier copy on this device): only these may be accepted unsigned, and they aren't offered for
   * decline. Written once, then only shrinks. Undefined before.
   */
  missing?: string[];
  /** Why `missing` was written: "pins" (the key pins were missing) or "device" (no earlier copy on this device). */
  missingWhy?: "pins" | "device";
  /**
   * The vaults this device had shown as usable before the account's signing identity was first generated here (null:
   * none, a new device), recorded once at that moment (rule 6): the only ones grandfathered when that identity turns
   * out to be made here, even if the first signed sync slips to a later unlock. Undefined when nothing was recorded;
   * cleared with `generated` once the key pins hold the own identity and the grandfathered list.
   */
  earlier?: string[] | null;
}

/** The device-local store (local storage in the apps; a map in tests). Failures read as nothing remembered. */
export interface KeyValueStore {
  get(key: string): string | null;
  set(key: string, value: string | null): void;
}

/** Device memory is per server and account: `<server origin>|<account id>`. */
export const trustScope = (origin: string, accountId: string) => `${origin}|${accountId}`;
export const MEMORY_PREFIX = "pa.vault-trust.";
export const PINS_PREFIX = "pa.key-pins.";
export const SEEN_PREFIX = "pa.vault-seen.";
export const memoryKey = (scope: string) => `${MEMORY_PREFIX}${scope}`;
export const pinsKey = (scope: string) => `${PINS_PREFIX}${scope}`;
export const seenKey = (scope: string) => `${SEEN_PREFIX}${scope}`;
/** Whether a local-storage key holds trust memory (kept when the desktop app changes server: it is per server and account). */
export const isTrustMemoryKey = (key: string) => key.startsWith(MEMORY_PREFIX) || key.startsWith(PINS_PREFIX) || key.startsWith(SEEN_PREFIX);

const GENERATED_MAX = 4;
/** Vault ids kept in the list of vaults seen here (more are never grandfathered: decline or accept by consent). */
export const SEEN_MAX = 5000;

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter(filled) : []);

/** The memory as stored: null when something is stored that can't be read (then nothing is written over it). */
function memoryState(store: KeyValueStore, scope: string): DeviceMemory | null {
  const out: DeviceMemory = { on: false, own: null, vaults: {}, generated: [] };
  const text = store.get(memoryKey(scope));
  if (text === null) return out;
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw)) return null;
  out.on = raw.on === true;
  out.own = filled(raw.own) ? raw.own : null;
  if (isRecord(raw.vaults)) {
    for (const [id, v] of Object.entries(raw.vaults)) {
      if (!isRecord(v)) continue;
      const m: VaultMemory = {};
      if (filled(v.roster) && rosterNumbers(v.roster)) m.roster = v.roster;
      if (v.signed === true) m.signed = true;
      out.vaults[id] = m;
    }
  }
  out.generated = strings(raw.generated).slice(-GENERATED_MAX);
  // Anything but a list reads as "no earlier copy" (nothing grandfathered: the safe side).
  if ("earlier" in raw) out.earlier = Array.isArray(raw.earlier) ? strings(raw.earlier) : null;
  if (Array.isArray(raw.missing)) {
    out.missing = strings(raw.missing);
    out.missingWhy = raw.missingWhy === "device" ? "device" : "pins";
  }
  return out;
}

/** The memory of an account on this device; malformed entries are left out (an unreadable record reads as empty). */
export function readMemory(store: KeyValueStore, scope: string): DeviceMemory {
  return memoryState(store, scope) ?? { on: false, own: null, vaults: {}, generated: [] };
}

/** Whether something is stored for the account's memory that can't be read (then the checks stay on, nothing is written over it). */
export const memoryUnreadable = (store: KeyValueStore, scope: string): boolean => memoryState(store, scope) === null;

/** The newer of two trusted rosters of a vault (by version; the first on a tie). */
function newerRoster(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  return (rosterNumbers(b)?.version ?? -1) > (rosterNumbers(a)?.version ?? -1) ? b : a;
}

export interface MemoryPatch {
  on?: boolean;
  own?: string;
  vaults?: Record<string, VaultMemory>;
  /** An identity hash generated here, before it is uploaded. */
  generated?: string;
  /** The vaults waiting without trust memory: written once (`why`), later only narrowed to `ids`. */
  missing?: { ids: string[]; why: "pins" | "device" };
  /** The vaults shown here before the identity was generated (null: none): written once, never replaced. */
  earlier?: string[] | null;
  /** The first signed sync is finished (own identity and grandfathered list in the pins): forget `generated` and `earlier`. */
  clearPending?: boolean;
}

/**
 * Write to the memory by merging (another tab or window may have written meanwhile): `on` and "seen signed" marks only
 * ever turn on, each vault keeps the higher roster version, the own identity, once written, is kept, and `missing` only
 * shrinks. Nothing is written when the stored record can't be read (it is never replaced by a guess). Returns the
 * memory as written, or null when nothing was.
 */
export function updateMemory(store: KeyValueStore, scope: string, patch: MemoryPatch): DeviceMemory | null {
  const m = memoryState(store, scope);
  if (!m) return null;
  if (patch.on) m.on = true;
  if (patch.own && !m.own) m.own = patch.own;
  for (const [id, v] of Object.entries(patch.vaults ?? {})) {
    const have = m.vaults[id] ?? {};
    const roster = newerRoster(have.roster, v.roster);
    m.vaults[id] = { ...(roster ? { roster } : {}), ...(have.signed || v.signed ? { signed: true } : {}) };
  }
  if (patch.generated && !m.generated.includes(patch.generated)) m.generated = [...m.generated, patch.generated].slice(-GENERATED_MAX);
  if (patch.earlier !== undefined && m.earlier === undefined) m.earlier = patch.earlier === null ? null : [...new Set(patch.earlier.filter(filled))].slice(0, SEEN_MAX);
  if (patch.clearPending) {
    m.generated = [];
    delete m.earlier;
  }
  if (patch.missing) {
    const ids = [...new Set(patch.missing.ids.filter(filled))];
    if (m.missing === undefined) {
      m.missing = ids;
      m.missingWhy = patch.missing.why;
    } else m.missing = m.missing.filter((id) => ids.includes(id));
  }
  const out: Record<string, unknown> = { on: m.on, own: m.own, vaults: m.vaults };
  if (m.generated.length) out.generated = m.generated;
  if (m.earlier !== undefined) out.earlier = m.earlier;
  if (m.missing !== undefined) {
    out.missing = m.missing;
    out.missingWhy = m.missingWhy;
  }
  store.set(memoryKey(scope), JSON.stringify(out));
  return m;
}

/**
 * The vault ids this device used for the account (per server and account), in any session, with or without signed
 * sharing: grandfathering at the first signed sync covers only vaults that were here in an earlier session (review
 * M-B). Null when nothing was ever recorded here (a new device, or the list can't be read).
 */
export function readSeen(store: KeyValueStore, scope: string): string[] | null {
  const text = store.get(seenKey(scope));
  if (text === null) return null;
  try {
    const v = JSON.parse(text) as unknown;
    return Array.isArray(v) ? strings(v) : null;
  } catch {
    return null;
  }
}

/** Add vault ids to the list (merged with what another tab wrote; at most `SEEN_MAX`; an unreadable list is left alone). */
export function addSeen(store: KeyValueStore, scope: string, ids: readonly string[]) {
  const text = store.get(seenKey(scope));
  const have = readSeen(store, scope);
  if (text !== null && have === null) return;
  const list = have ?? [];
  const known = new Set(list);
  const add = ids.filter((id) => filled(id) && !known.has(id));
  if (have !== null && add.length === 0) return;
  store.set(seenKey(scope), JSON.stringify([...list, ...add].slice(0, SEEN_MAX)));
}

/** This device's copy of the account's key pins: sealed with the account key as version `seq`; `dirty`: not on the server yet. */
export interface LocalPins {
  seq: number;
  sealed: string;
  dirty: boolean;
}

/** The local copy as stored: null when there is none, "unreadable" when something is stored that can't be read. */
export function localPinsState(store: KeyValueStore, scope: string): LocalPins | null | "unreadable" {
  const text = store.get(pinsKey(scope));
  if (text === null) return null;
  try {
    const v = JSON.parse(text) as unknown;
    if (!isRecord(v) || !wholeNumber(v.seq) || !filled(v.sealed)) return "unreadable";
    return { seq: v.seq, sealed: v.sealed, dirty: v.dirty === true };
  } catch {
    return "unreadable";
  }
}

export function readLocalPins(store: KeyValueStore, scope: string): LocalPins | null {
  const s = localPinsState(store, scope);
  return s === "unreadable" ? null : s;
}

/**
 * Keep the local copy with the higher version: a copy another tab wrote with a higher `seq` isn't written over, and
 * nothing is written over a stored copy that can't be read. (Merging a same-version unsent copy of another tab is
 * `signed-sharing.ts`'s job: it needs the account key.) Returns whether it was written.
 */
export function writeLocalPins(store: KeyValueStore, scope: string, pins: LocalPins): boolean {
  const have = localPinsState(store, scope);
  if (have === "unreadable") return false;
  if (have && have.seq > pins.seq) return false;
  store.set(pinsKey(scope), JSON.stringify(pins));
  return true;
}

// ----------------------------------------------------------------- wording

export const SHARING_PAUSED = "Your server lists a signing key that isn't yours. Sharing is paused on this device.";
export const VAULT_REFUSED = "PassAuth couldn't verify this shared vault's key, so it isn't used. Ask its owner, or your server's admin.";
export const VAULT_UNOPENABLE = "One vault couldn't be opened: its key may have been replaced. Ask the person who manages it to share it with you again.";
export const TOO_MANY_CHANGES = "This shared vault has too many changes to check here, so it isn't used. Ask its owner, or your server's admin.";
export const VAULT_LEFT = "You left or declined this vault. It isn't used unless it's shared with you again.";
export const PINS_ROLLED_BACK = "Your server sent an older list of known keys. PassAuth keeps using the list this device saw last.";
export const PINS_UNREADABLE = "Your server's list of known keys couldn't be opened. PassAuth keeps using the list this device saw last.";
export const NEW_DEVICE =
  "This device had no earlier copy of your shared vaults, so each one shared before signing needs your OK once here. Accept only the ones you expected.";
export const TRUST_MEMORY_MISSING =
  "PassAuth couldn't find your list of known keys on your server, so each shared vault needs your OK again. If you didn't expect this, tell your server's admin.";
export const ACCOUNT_MISMATCH = "Your server answered for another account. Nothing was changed. Sign out, then sign in again.";
export const NOT_YET_SIGNED = "Not yet signed";
export const MEMBERS_SIGNED_UPDATE = "This vault's members are signed, and this device can't sign changes right now. Reload the page, then try again.";
export const FIRST_SIGNED = "First time this vault is signed: compare these fingerprints with the people.";
export const AUTOMATIC_NEEDS_REVIEW =
  "This vault's list of members isn't signed yet, so PassAuth didn't replace its key automatically. Open the vault in Settings, Vaults & sharing, and replace its key there.";

/**
 * An unsigned shared vault before this device finished the account's first signed sync (the server hasn't shown it
 * signs, the identity state isn't known yet, or the grandfathered list isn't written): neither used nor offered for
 * consent yet (rule 2).
 */
export const STILL_CHECKING = "PassAuth is still checking this shared vault. It's used once the check is finished.";
/** An unsigned vault needing consent that can't be accepted unsigned: held, never offered for decline (rule 1). */
export const ASK_OWNER_TO_SIGN = "Ask the vault's owner to sign this vault.";
/** This device's trust memory is stored but can't be read: shared vaults aren't used and nothing about them is changed (rule 7). */
export const MEMORY_UNREADABLE =
  "PassAuth couldn't read what this device remembers about your shared vaults, so they aren't used here and nothing about them is changed. Your own vaults still work.";
/** 429 `rate_limited` on a key replacement (30 per vault and hour). */
export const KEY_REPLACEMENTS_LIMIT =
  "This vault's key was replaced many times in the last hour, so your server asks to wait. Nothing was changed. Try again later.";

/** Why a vault was refused (`pinsAdmit` reasons), in words. */
export function refusedText(reason: string): string {
  if (reason === "paused") return SHARING_PAUSED;
  if (reason === "left") return VAULT_LEFT;
  return VAULT_REFUSED;
}

/** Someone's keys changed since they were pinned: whatever needed them stops. */
export const keysChangedText = (email: string) => `${cleanText(email) || "This person"}'s keys changed. Compare their fingerprint with them before you continue.`;

/** A new account uses an email already pinned for another account: whatever needed it stops (review L-C wording). */
export const emailConflictText = (email: string) => {
  const who = cleanText(email) || "this email";
  return `A different account uses ${who}. Trust it only if ${who} deleted their account and made a new one.`;
};

/** The first share with someone: their identity is pinned now; the fingerprint check is what makes it a proof. */
export const firstTimeText = (email: string) => `First time you share with ${cleanText(email) || "this person"}: compare this fingerprint with them.`;

/** An invitation without a share signature on a server that signs: it can only be declined. */
export const unsignedInvitationText = (who: string) => `This invitation isn't signed. Ask ${cleanText(who) || "them"} to update PassAuth and share again.`;

/** A vault accepted before whose key an app that doesn't sign replaced. */
export const replacedText = (vault: string) =>
  `The key of "${cleanText(vault) || "a shared vault"}" was replaced by an app that doesn't sign yet. Accept only if someone in this vault just replaced its key.`;

/**
 * A vault accepted before, never seen signed, whose new key is signed for the first time (`consent.replaced` with a
 * signer): `who` is the signer's pinned email, else "someone listed by your server as <email>".
 */
export const replacedSignedText = (vault: string, who: string) =>
  `The key of "${cleanText(vault) || "a shared vault"}" was replaced and signed by ${cleanText(who) || "someone on this server"} for the first time. Compare their fingerprint before you accept.`;

/** `consent.own`: the account held this vault with its own key wrap. */
export const ownVaultReplacedText = (vault: string) =>
  `"${cleanText(vault) || "This vault"}" was your own vault. Your server now says someone else gave you a new key for it. Accept only if you shared this vault and expected a key change.`;

/** A vault the server put in the account without an invitation it accepted. */
export const consentText = (vault: string) => `Your server added "${cleanText(vault) || "a shared vault"}" to your account. Accept only if you expected it.`;

/** "listed by your server as …" when the server lists another email than the one pinned; null otherwise. */
export function listedAs(pinned: string | null | undefined, listed: string | null | undefined): string | null {
  const p = cleanText(pinned);
  const l = cleanText(listed);
  if (!p || !l || p.toLowerCase() === l.toLowerCase()) return null;
  return `listed by your server as ${l}`;
}

/** "Signed by <pinned email, else the one the server kept>", with "(account deleted)" once the signer's account is gone. */
export function signedByText(pinnedEmail: string | null, signer: { name: string; email: string }, deleted: boolean): string {
  const who = cleanText(pinnedEmail) || cleanText(signer.email) || cleanText(signer.name) || "someone on this server";
  return deleted ? `Signed by ${who} (account deleted)` : `Signed by ${who}`;
}

/** What a member list differs in, as `compareMembers` says (user ids). */
export interface MemberDiff {
  unknown: string[];
  identity_changed: string[];
  role_changed: string[];
  missing: string[];
}

export const diffIsClean = (d: MemberDiff) => d.unknown.length === 0 && d.identity_changed.length === 0 && d.role_changed.length === 0;

/** Someone by a user id, as the people they are (a pinned email first, then the listed email or name); never the raw id. */
export type NameOf = (userId: string) => string | null;

/** User ids as the people they are; ids nobody knows become "someone your server lists". */
export function peopleNames(ids: readonly string[], nameOf: NameOf): string[] {
  let unknown = 0;
  const out: string[] = [];
  for (const id of new Set(ids)) {
    const n = cleanText(nameOf(id));
    if (n) out.push(n);
    else unknown++;
  }
  if (unknown === 1) out.push("someone your server lists");
  else if (unknown > 1) out.push(`${unknown} people your server lists`);
  return out;
}

/** A name resolver from rows with emails and names (cleaned). */
export const namesFromRows =
  (rows: readonly { user_id: string; email: string; name: string }[]): NameOf =>
  (id) => {
    const r = rows.find((m) => m.user_id === id);
    return r ? cleanText(r.email) || cleanText(r.name) || null : null;
  };

/** Stops a key replacement or share: the server lists members the vault's signed member list doesn't. */
export function membersDifferText(ids: readonly string[], nameOf: NameOf, what = "didn't change the key"): string {
  return `The server lists members your vault's signed member list doesn't: ${peopleNames(ids, nameOf).join(", ")}. PassAuth ${what}.`;
}

/**
 * A server's 409 `members_changed` fields (`unknown`, `identity_changed`, `role_changed`, `missing`: user ids): the diff
 * when every list is a list of strings, else null.
 */
export function readMemberDiff(v: unknown): MemberDiff | null {
  if (!isRecord(v)) return null;
  const list = (x: unknown) => (Array.isArray(x) && x.every((s) => typeof s === "string") ? (x as string[]) : null);
  const unknown = list(v.unknown ?? []);
  const changed = list(v.identity_changed ?? []);
  const role = list(v.role_changed ?? []);
  const missing = list(v.missing ?? []);
  if (!unknown || !changed || !role || !missing) return null;
  return { unknown, identity_changed: changed, role_changed: role, missing };
}
