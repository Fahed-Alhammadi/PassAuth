/**
 * Emergency access (servers with the `emergency_access` feature): someone (the grantor) names a trusted contact with an
 * account on the same server and a waiting period of 1–90 days. invited → (the contact accepts) accepted → (the
 * grantor checks the contact's fingerprint with them and confirms) confirmed → (the contact asks) requested → (the
 * grantor approves, or the waiting period ends) approved. The grantor may reject a request or end an approved access
 * (rejected; the contact may ask again); either side may remove it.
 *
 * Keys (servers with `emergency_vault_keys`): confirming makes an emergency key for the access, seals it to the contact's
 * public key, keeps it wrapped by the grantor's account key (`grantor_key`) and wraps each personal vault's key with it
 * (a vault the grantor owns with their own key and nobody else is in, not even invited). The grantor's apps add wraps
 * for personal vaults that get none (`missing_vaults`: a new vault, one no longer shared, one whose key was replaced).
 * Removing a contact who held the key makes the server ask for new keys of those vaults; the app replaces them.
 *
 * The roster: which accesses the grantor's apps may add wraps for, kept by the server sealed with the account key (it
 * can neither read nor change it) and versioned inside. Confirming adds an access before the server hears of the key,
 * removing takes it out first; wraps are added only for an access whose id, contact key and `grantor_key` (by hash)
 * are in it. Each device remembers the highest version it opened and takes no older one (a server sending back a
 * removed contact), and says so.
 *
 * An approved contact can view those personal vaults, read-only. Limits, said plainly in the app: the waiting period
 * is the server's rule, not encryption, and a contact who was approved keeps what they saw.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `emergency.test.ts`.
 */
import { oneLine } from "./text";
import type { EncryptedItem, KeyKind, Role } from "./types";

export type GrantStatus = "invited" | "accepted" | "confirmed" | "requested" | "approved" | "rejected";
const STATUSES: GrantStatus[] = ["invited", "accepted", "confirmed", "requested", "approved", "rejected"];

export interface GrantPerson {
  id: string;
  email: string;
  name: string;
  /** For the fingerprint shown before confirming. */
  publicKey: string;
}

export interface Grant {
  id: string;
  status: GrantStatus;
  waitDays: number;
  createdAt: number;
  updatedAt: number;
  requestedAt: number | null;
  approvedAt: number | null;
  /** While a request waits: when the server approves it unless the grantor answers. */
  autoApproveAt: number | null;
  grantor: GrantPerson;
  grantee: GrantPerson;
  // What the grantor's listing adds (servers with `emergency_vault_keys`; empty for the contact and older servers).
  /** The key scheme (2: an emergency key over the personal vaults); null when not given. */
  keyVersion: number | null;
  /** The access's emergency key wrapped by this account's key, once confirmed. */
  grantorKey: string | null;
  /** Confirmed before emergency keys: the grantor confirms the contact again. */
  reconfirm: boolean;
  /** Personal vaults without a wrap for this access (when accepted: the vaults to wrap when confirming). */
  missingVaults: string[];
  /** Confirmed before emergency keys, when the contact got the account key itself: they may keep it. */
  v1Exposed: boolean;
}

/** The key scheme this app makes and opens: an emergency key per access over the personal vault keys. */
export const KEY_VERSION = 2;

/** Shortest and longest waiting period the server accepts, in days. */
export const MIN_WAIT_DAYS = 1;
export const MAX_WAIT_DAYS = 90;
/** The waiting period offered first. */
export const DEFAULT_WAIT_DAYS = 7;

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const strings = (v: unknown): string[] => (Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string" && x !== ""))] : []);

function readPerson(v: unknown): GrantPerson | null {
  if (!v || typeof v !== "object") return null;
  const p = v as Record<string, unknown>;
  return str(p.id) ? { id: str(p.id), email: str(p.email), name: str(p.name), publicKey: str(p.public_key) } : null;
}

/** One emergency access from the API, or null when malformed (an unknown status included). */
export function readGrant(value: unknown): Grant | null {
  if (!value || typeof value !== "object") return null;
  const g = value as Record<string, unknown>;
  const grantor = readPerson(g.grantor);
  const grantee = readPerson(g.grantee);
  const status = STATUSES.find((s) => s === g.status);
  const waitDays = num(g.wait_days);
  if (!str(g.id) || !grantor || !grantee || !status || waitDays === null) return null;
  return {
    id: str(g.id),
    status,
    waitDays,
    createdAt: num(g.created_at) ?? 0,
    updatedAt: num(g.updated_at) ?? 0,
    requestedAt: num(g.requested_at),
    approvedAt: num(g.approved_at),
    autoApproveAt: num(g.auto_approve_at),
    grantor,
    grantee,
    keyVersion: num(g.key_version),
    grantorKey: str(g.grantor_key) || null,
    reconfirm: g.reconfirm === true,
    missingVaults: strings(g.missing_vaults),
    v1Exposed: g.v1_exposed === true,
  };
}

/** `GET /emergency-access`: the accesses both ways, and the account's sealed roster with its sequence number. */
export interface GrantLists {
  asGrantor: Grant[];
  asGrantee: Grant[];
  /** The roster as the server keeps it (sealed); null until one is stored, or from servers without it. */
  roster: string | null;
  /** The roster's sequence number (`PUT /emergency-access/roster` sends the next one); null from servers without it. */
  rosterSeq: number | null;
}

/** `GET /emergency-access`: the contacts the account named, the people who named it, and the roster. */
export function readGrants(value: unknown): GrantLists {
  const v = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const list = (x: unknown) => (Array.isArray(x) ? x.map(readGrant).filter((g): g is Grant => g !== null) : []);
  const seq = num(v.roster_seq);
  return {
    asGrantor: list(v.as_grantor),
    asGrantee: list(v.as_grantee),
    roster: str(v.roster) || null,
    rosterSeq: seq !== null && Number.isInteger(seq) && seq >= 0 ? seq : null,
  };
}

/** A person's name, else their email address. */
export const personName = (p: GrantPerson): string => p.name.trim() || p.email || "Someone";

/** "1 day", "7 days". */
export const daysText = (days: number): string => `${days} ${days === 1 ? "day" : "days"}`;

/** A waiting period the server accepts: a whole number of days from 1 to 90. */
export const validWait = (days: number): boolean => Number.isInteger(days) && days >= MIN_WAIT_DAYS && days <= MAX_WAIT_DAYS;

export type Tone = "ok" | "warn" | "info";

/** What a contact confirmed before emergency keys may still hold, said wherever removing them is offered. */
export const v1Warning = (who: string): string =>
  `${who} was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account.`;

/**
 * What confirming a contact (`who`) means, said before it is done (the confirm step and the add form). For a contact
 * who got the account key before (`v1Exposed`), the promise about removing them gives way to what it can't undo.
 */
export function confirmMeaning(who: string, v1Exposed = false): string {
  const gives = `Confirming gives ${who} a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach.`;
  return v1Exposed
    ? `${gives} ${v1Warning(who)}`
    : `${gives} If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised.`;
}

/** Why a contact confirmed before emergency keys has to be confirmed again. */
export const reconfirmText = (who: string): string =>
  `PassAuth now gives emergency contacts a key to your personal vaults only. Confirm ${who} again to give them access.`;

/** Statuses in which an access holds its keys: the contact has (or may get) the emergency key. */
export const hasKeys = (g: Grant): boolean => g.status === "confirmed" || g.status === "requested" || g.status === "approved" || g.status === "rejected";

/** What removing the contact of `g` does, for the grantor's confirmation. */
export function removalText(g: Grant): string {
  const who = personName(g.grantee);
  const v1 = g.v1Exposed ? ` ${v1Warning(who)}` : "";
  if (!hasKeys(g)) return `${who} can't ask for access any more.${v1}`;
  const changes = "Changing a vault's key also deletes the earlier versions kept of its items.";
  if (g.v1Exposed) return `${who} can't ask for access any more, and PassAuth changes the keys of your personal vaults. ${changes}${v1}`;
  const kept = g.status === "confirmed" ? "" : " If they had access, they keep what they saw: change the passwords that matter if you no longer trust them.";
  return `${who} can't ask for access any more, and PassAuth changes the keys of your personal vaults, so they can't read anything you add afterwards, unless your server is later compromised. ${changes}${kept}`;
}

/** What a status means to the grantor, about their contact `who`. `when` formats Unix seconds. */
export function grantorStatus(g: Grant, when: (seconds: number) => string): { label: string; text: string; tone: Tone } {
  const who = personName(g.grantee);
  switch (g.status) {
    case "invited":
      return { label: "Invited", text: `Waiting for ${who} to accept.`, tone: "info" };
    case "accepted":
      return g.reconfirm
        ? { label: "Confirm again", text: reconfirmText(who), tone: "warn" }
        : { label: "Confirm", text: `${who} accepted. Check their fingerprint with them, then confirm them.`, tone: "warn" };
    case "confirmed":
      return { label: "Ready", text: `${who} can ask for access. You'd have ${daysText(g.waitDays)} to say no.`, tone: "ok" };
    case "requested":
      return {
        label: "Access requested",
        text:
          g.autoApproveAt !== null
            ? `${who} asked for access${g.requestedAt !== null ? ` on ${when(g.requestedAt)}` : ""}. Unless you reject it, they can view your personal vaults from ${when(g.autoApproveAt)}.`
            : `${who} asked for access. Unless you reject it, they can view your personal vaults after ${daysText(g.waitDays)}.`,
        tone: "warn",
      };
    case "approved":
      return { label: "Has access", text: `${who} can view your personal vaults${g.approvedAt !== null ? ` since ${when(g.approvedAt)}` : ""}.`, tone: "warn" };
    case "rejected":
      return { label: "Rejected", text: `You rejected ${who}'s last request. They can ask again.`, tone: "info" };
  }
}

/** What a status means to the contact, about the person `who` who named them. */
export function granteeStatus(g: Grant, when: (seconds: number) => string): { label: string; text: string; tone: Tone } {
  const who = personName(g.grantor);
  switch (g.status) {
    case "invited":
      return { label: "Invitation", text: `${who} named you as their emergency contact. Accept to be able to ask for access to their vaults if you ever need to.`, tone: "info" };
    case "accepted":
      return { label: "Waiting", text: `Waiting for ${who} to confirm you.`, tone: "info" };
    case "confirmed":
      return { label: "Ready", text: `You can ask for access. ${who} is told at once and has ${daysText(g.waitDays)} to say no.`, tone: "ok" };
    case "requested":
      return {
        label: "Requested",
        text:
          g.autoApproveAt !== null
            ? `You asked for access. Unless ${who} rejects it, you can view their vaults from ${when(g.autoApproveAt)}.`
            : `You asked for access. Unless ${who} rejects it, you can view their vaults after ${daysText(g.waitDays)}.`,
        tone: "warn",
      };
    case "approved":
      return { label: "Access granted", text: `You can view ${who}'s vaults.`, tone: "ok" };
    case "rejected":
      return { label: "Rejected", text: `${who} rejected your request. You can ask again.`, tone: "info" };
  }
}

export type GrantorAction = "confirm" | "approve" | "reject" | "end" | "wait" | "remove";
export type GranteeAction = "accept" | "decline" | "request" | "view" | "remove";

/** What the grantor can do now, most important first. */
export function grantorActions(g: Grant): GrantorAction[] {
  switch (g.status) {
    case "accepted":
      return ["confirm", "wait", "remove"];
    case "requested":
      return ["approve", "reject", "wait", "remove"];
    case "approved":
      return ["end", "wait", "remove"];
    default:
      return ["wait", "remove"];
  }
}

/** What the contact can do now, most important first. */
export function granteeActions(g: Grant): GranteeAction[] {
  switch (g.status) {
    case "invited":
      return ["accept", "decline"];
    case "confirmed":
    case "rejected":
      return ["request", "remove"];
    case "approved":
      return ["view", "remove"];
    default:
      return ["remove"];
  }
}

/** Grants that want the account's answer: contacts to confirm, requests to answer, invitations to accept. */
export function needsAnswer(grants: { asGrantor: Grant[]; asGrantee: Grant[] }): number {
  return grants.asGrantor.filter((g) => g.status === "accepted" || g.status === "requested").length + grants.asGrantee.filter((g) => g.status === "invited").length;
}

// -------------------------------------------------------------- the keys

/** A vault as this app's own sync shows it. */
export interface OwnVault {
  id: string;
  role: Role;
  kind: KeyKind;
}

/**
 * Whether this app's own data says a vault is personal, the only kind whose key an emergency contact may get: the
 * account owns it with its own key (`role` owner, `kind` account) and its members (`GET /vaults/{id}/members`, invitees
 * included) are this account (`me`) alone. Unknown vaults and members lists aren't.
 */
export function isPersonal(vault: OwnVault | undefined, members: readonly { user_id: string }[] | null | undefined, me: string): boolean {
  if (!vault || vault.role !== "owner" || vault.kind !== "account" || !me || !members) return false;
  return members.length === 1 && members[0].user_id === me;
}

/**
 * Which of the vaults the server asks to wrap (`wanted`) this app wraps: only those its own data says are personal
 * (`personal`). `refused`: the others, never wrapped (confirming stops on them; adding wraps leaves them out).
 */
export function vaultsToWrap(wanted: readonly string[], personal: (vaultId: string) => boolean): { wrap: string[]; refused: string[] } {
  const wrap: string[] = [];
  const refused: string[] = [];
  for (const id of new Set(wanted)) (personal(id) ? wrap : refused).push(id);
  return { wrap, refused };
}

/** The accesses whose wraps this account should add now: holding keys, with this account's `grantor_key`, vaults missing. */
export function accessesToFill(grants: readonly Grant[]): Grant[] {
  return grants.filter((g) => hasKeys(g) && g.grantorKey !== null && g.missingVaults.length > 0 && (g.keyVersion ?? KEY_VERSION) === KEY_VERSION);
}

/** The vault ids of an answer that asks for new keys (`rotation_pending` of `DELETE /emergency-access/{id}`). */
export const vaultsToRotate = (answer: unknown): string[] =>
  answer && typeof answer === "object" ? strings((answer as Record<string, unknown>).rotation_pending) : [];

/**
 * The vaults whose keys the grantor's app replaces after removing a contact: those the server names that this app's
 * own data says are personal (`personal`). A server can't make it replace the keys of a shared vault this way.
 */
export const vaultsToReKey = (answer: unknown, personal: (vaultId: string) => boolean): string[] => vaultsToWrap(vaultsToRotate(answer), personal).wrap;

// ------------------------------------------------------------- the roster

/** One access the grantor's apps may add wraps for. */
export interface RosterEntry {
  id: string;
  /** The contact's public key the grantor checked by its fingerprint. */
  contactKey: string;
  /** SHA-256 of the access's `grantor_key`, base64url. */
  grantorKeyHash: string;
  /** The contact's email address and name as the grantor saw them when confirming (missing in entries from before). */
  email?: string;
  name?: string;
}

/** An access taken off the roster for good (removed by the grantor, or dropped when the server stopped listing it). */
export interface RemovedEntry {
  id: string;
  /** SHA-256 of its `grantor_key`, base64url ("" when it never had one). */
  grantorKeyHash: string;
}

/**
 * The roster's JSON (inside the sealed box): its version, the accesses, and those removed for good (`removed`, oldest
 * first): no fill and no "Confirm again" for them; to give such a contact access again, the grantor adds them as a new
 * contact (a new access).
 */
export interface Roster {
  version: number;
  accesses: RosterEntry[];
  removed: RemovedEntry[];
}

/** SHA-256 of `text` (UTF-8), base64url: how the roster names an access's `grantor_key`. */
export async function sha256b64(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The roster before any is stored. */
export const EMPTY_ROSTER: Roster = { version: 0, accesses: [], removed: [] };

/** Most removed accesses a roster keeps; the oldest go first. */
export const MAX_REMOVED = 300;
/** The largest sealed roster the server takes (base64url characters). */
export const MAX_SEALED_ROSTER = 48 * 1024;

/** Longest email and name a roster entry keeps (an email address has at most 254 characters). */
export const MAX_EMAIL = 254;
export const MAX_NAME = 100;

/** A roster from its JSON (as the core opened it); null when malformed. Rosters from before `removed` have none. */
export function readRoster(json: string): Roster | null {
  let v: unknown;
  try {
    v = JSON.parse(json);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (typeof r.version !== "number" || !Number.isInteger(r.version) || r.version < 0 || !Array.isArray(r.accesses)) return null;
  if (r.removed !== undefined && !Array.isArray(r.removed)) return null;
  const accesses: RosterEntry[] = [];
  for (const raw of r.accesses) {
    const e = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
    if (!e || !str(e.id) || !str(e.contact_key) || !str(e.grantor_key_hash)) return null;
    if ((e.email !== undefined && typeof e.email !== "string") || (e.name !== undefined && typeof e.name !== "string")) return null;
    accesses.push({
      id: str(e.id),
      contactKey: str(e.contact_key),
      grantorKeyHash: str(e.grantor_key_hash),
      ...(typeof e.email === "string" ? { email: e.email } : {}),
      ...(typeof e.name === "string" ? { name: e.name } : {}),
    });
  }
  const removed: RemovedEntry[] = [];
  for (const raw of (r.removed as unknown[] | undefined) ?? []) {
    const e = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
    if (!e || !str(e.id) || typeof e.grantor_key_hash !== "string") return null;
    removed.push({ id: str(e.id), grantorKeyHash: e.grantor_key_hash });
  }
  return { version: r.version, accesses, removed };
}

/** The roster's JSON, for `Account.sealEmergencyRoster`. */
export const rosterJson = (r: Roster): string =>
  JSON.stringify({
    version: r.version,
    accesses: r.accesses.map((e) => ({
      id: e.id,
      contact_key: e.contactKey,
      grantor_key_hash: e.grantorKeyHash,
      ...(e.email !== undefined ? { email: e.email } : {}),
      ...(e.name !== undefined ? { name: e.name } : {}),
    })),
    removed: r.removed.map((x) => ({ id: x.id, grantor_key_hash: x.grantorKeyHash })),
  });

/** How long `r` is once sealed (base64url of version, nonce, the JSON and the tag). */
export function sealedLength(r: Roster): number {
  const n = 1 + 24 + new TextEncoder().encode(rosterJson(r)).length + 16;
  return Math.floor(n / 3) * 4 + [0, 2, 3][n % 3];
}

/** The roster would pass the server's size limit: nothing is written (removed contacts are never dropped to make room). */
export class RosterFullError extends Error {
  constructor() {
    super("Your list of emergency contacts is full. Remove a contact you no longer need, then try again.");
    this.name = "RosterFullError";
  }
}

/**
 * `removed` and then `add`, each access once (a later copy counts as newer), the oldest trimmed beyond `MAX_REMOVED`.
 * A roster that would still pass the server's size limit is refused (`RosterFullError`): trimming removed entries to
 * make room would let padded names or emails push removed contacts out.
 */
function withRemoved(r: Omit<Roster, "removed">, removed: readonly RemovedEntry[], add: readonly RemovedEntry[] = []): Roster {
  const all: RemovedEntry[] = [];
  for (const x of [...removed, ...add]) {
    const i = all.findIndex((y) => y.id === x.id);
    if (i >= 0) all.splice(i, 1);
    all.push(x);
  }
  const out: Roster = { ...r, removed: all.slice(-MAX_REMOVED) };
  if (sealedLength(out) > MAX_SEALED_ROSTER) throw new RosterFullError();
  return out;
}

/** Whether `r` took access `id` (or its key, by hash) off for good. */
export const isRemoved = (r: Roster | null, id: string, grantorKeyHash: string | null = null): boolean =>
  !!r?.removed.some((x) => x.id === id || (!!grantorKeyHash && x.grantorKeyHash === grantorKeyHash));

/** A roster entry for access `g` as the grantor confirms it: the contact key they checked, the name and email shown. */
export function rosterEntry(g: Grant, checkedContactKey: string, grantorKeyHash: string): RosterEntry {
  // One line without invisible characters, and bounded: the server chooses these strings, and padding them must not
  // crowd anything else out of the sealed roster.
  return { id: g.id, contactKey: checkedContactKey, grantorKeyHash, email: oneLine(g.grantee.email, MAX_EMAIL), name: oneLine(g.grantee.name, MAX_NAME) };
}

/** The entries whose access the server still lists, in any state: the others ended (by either side, or with an account). */
export const pruneRoster = (r: Roster, listed: ReadonlySet<string>): RosterEntry[] => r.accesses.filter((e) => listed.has(e.id));

const removedOf = (e: RosterEntry): RemovedEntry => ({ id: e.id, grantorKeyHash: e.grantorKeyHash });

/**
 * The next roster after `r`: entries of accesses the server no longer lists (`listed`) dropped and kept as removed, then
 * `add` added (replacing one of the same access), or access `remove` taken out and kept as removed (with `hash`, its
 * `grantor_key` hash, when the roster has no entry for it), or null: only the dropping. Removed accesses are never
 * dropped (but the oldest beyond the cap). Its version is one above both `r`'s and `seen` (the highest this device has
 * opened), so no device takes it for an older one. Null when nothing changes.
 */
export function nextRoster(
  r: Roster,
  seen: number,
  change: { add: RosterEntry } | { remove: string; hash?: string } | null,
  listed: ReadonlySet<string> | null = null,
): Roster | null {
  let accesses = listed ? pruneRoster(r, listed) : [...r.accesses];
  const gone: RemovedEntry[] = r.accesses.filter((e) => !accesses.includes(e)).map(removedOf);
  if (change && "add" in change) {
    accesses = accesses.filter((e) => e.id !== change.add.id);
    accesses.push(change.add);
  } else if (change) {
    const entry = accesses.find((e) => e.id === change.remove) ?? r.accesses.find((e) => e.id === change.remove);
    accesses = accesses.filter((e) => e.id !== change.remove);
    if (entry || change.hash !== undefined) gone.push({ id: change.remove, grantorKeyHash: entry?.grantorKeyHash ?? change.hash ?? "" });
  }
  const next = withRemoved({ version: Math.max(r.version, seen) + 1, accesses }, r.removed, gone);
  return rosterJson({ ...next, version: r.version }) === rosterJson(r) ? null : next;
}

/**
 * Accesses that hold keys but that the (trusted) roster doesn't list and didn't remove: the fill gives them nothing
 * until the grantor confirms them again (left out by a write that got lost, or after "Start a new list").
 */
export const needsConfirmAgain = (g: Grant, roster: Roster | null, grantorKeyHash: string | null = null): boolean =>
  roster !== null && hasKeys(g) && !roster.accesses.some((e) => e.id === g.id) && !isRemoved(roster, g.id, grantorKeyHash);

/** What the app says about an access the roster removed (it is never confirmed again: a new contact is). */
export const removedText = (who: string): string => `${who} was removed from your emergency contacts. To give them access again, add them as a new contact.`;

/** A roster entry as the grantor reviews it: its own name and email (from inside the roster), or "Unknown contact". */
export const entryLabel = (e: RosterEntry): string => {
  const name = e.name?.trim();
  if (name && e.email) return `${name} (${e.email})`;
  return name || e.email || "Unknown contact";
};

/** One entry of the server's roster under review, and what taking the list would do for it. */
export interface ReviewedEntry {
  entry: RosterEntry;
  /** Not in this device's last trusted roster (or no such roster here): taking the list lets them in again. */
  wouldReturn: boolean;
  /** Removed for good (by the server's list or this device's own): shown, never written back. */
  removed: boolean;
}

/**
 * The server's roster as the grantor reviews it before "Use the server's list": only entries for accesses the server
 * lists, each marked when this device's last trusted roster (`trusted`; null: none kept here) has no entry with the
 * same access and contact key, or when either list removed it.
 */
export function reviewRoster(server: Roster, trusted: Roster | null, listed: ReadonlySet<string>): ReviewedEntry[] {
  return pruneRoster(server, listed).map((entry) => ({
    entry,
    wouldReturn: !trusted?.accesses.some((t) => t.id === entry.id && t.contactKey === entry.contactKey),
    removed: isRemoved(server, entry.id, entry.grantorKeyHash) || isRemoved(trusted, entry.id, entry.grantorKeyHash),
  }));
}

/** Whether `r` is older than the highest roster version this device has opened (`seen`): never act on it. */
export const rosterIsOlder = (r: Roster, seen: number): boolean => r.version < seen;

/**
 * "Use the server's list", after the server's admin restored a backup: exactly the entries the grantor was shown
 * (`shown`, from `reviewRoster`), less those removed and those the server no longer lists now (`listedNow`), as a new
 * roster one version above the newest this device saw (`seen`) and the server's (`server`). Nothing that wasn't shown is
 * ever added: entries of the server's roster that weren't shown (the server didn't list them at the review) are kept
 * as removed, as are the shown ones it no longer lists, next to everything the server's list and this device's own
 * (`trusted`) removed. Once it is stored and remembered, every older version, the ones in between included, is refused.
 */
export function restoredRosterForward(
  shown: readonly ReviewedEntry[],
  server: Roster,
  trusted: Roster | null,
  seen: number,
  listedNow: ReadonlySet<string>,
): Roster {
  const accesses = shown.filter((r) => !r.removed && listedNow.has(r.entry.id)).map((r) => r.entry);
  const gone = server.accesses.filter((e) => !accesses.some((a) => a.id === e.id)).map(removedOf);
  for (const r of shown) if (!accesses.includes(r.entry) && !gone.some((x) => x.id === r.entry.id)) gone.push(removedOf(r.entry));
  return withRemoved({ version: Math.max(seen, server.version) + 1, accesses }, [...server.removed, ...(trusted?.removed ?? [])], gone);
}

/**
 * "Start a new list" when the server's roster doesn't open: an empty one above the newest this device saw, keeping the
 * accesses this device's last trusted roster (`trusted`) removed.
 */
export const freshRoster = (seen: number, trusted: Roster | null = null): Roster =>
  withRemoved({ version: seen + 1, accesses: [] }, trusted?.removed ?? []);

/**
 * The accesses the fill may add wraps for: those `accessesToFill` lists whose id, contact public key and `grantor_key`
 * (by its hash in `hashes`) are in the roster and that it didn't remove. An access the server lists but the roster
 * doesn't (removed, ended, or made up) gets nothing.
 */
export function fillableAccesses(grants: readonly Grant[], roster: Roster, hashes: ReadonlyMap<string, string>): Grant[] {
  return accessesToFill(grants).filter((g) => {
    const hash = g.grantorKey !== null ? (hashes.get(g.grantorKey) ?? null) : null;
    return !isRemoved(roster, g.id, hash) && roster.accesses.some((e) => e.id === g.id && e.contactKey === g.grantee.publicKey && hash !== null && e.grantorKeyHash === hash);
  });
}

// ------------------------------------------------------------- the vault

/** `GET /emergency-access/{id}/vault`: the sealed emergency key, the grantor's wrapped personal vaults and all their items. */
export interface GrantorVaultData {
  /** The key scheme; null from servers before emergency keys (whose sealed key this app can't open). */
  keyVersion: number | null;
  sealedKey: string;
  vaults: { id: string; meta: string; wrappedKey: string }[];
  items: { row: EncryptedItem; deletedAt: number | null; updatedAt: number }[];
}

/** The answer as the core takes it (`item_key` becomes `key`, as `VaultKey.decryptItem` expects); null when malformed. */
export function readGrantorVault(value: unknown): GrantorVaultData | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  const sealedKey = str(v.sealed_key);
  if (!sealedKey || !Array.isArray(v.vaults) || !Array.isArray(v.items)) return null;
  const vaults: GrantorVaultData["vaults"] = [];
  for (const raw of v.vaults) {
    const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
    if (r && str(r.id) && str(r.meta) && str(r.wrapped_key)) vaults.push({ id: str(r.id), meta: str(r.meta), wrappedKey: str(r.wrapped_key) });
  }
  const items: GrantorVaultData["items"] = [];
  for (const raw of v.items) {
    const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
    if (!r || !str(r.id) || !str(r.vault_id) || !str(r.item_key) || !str(r.data)) continue;
    items.push({
      row: { id: str(r.id), vault_id: str(r.vault_id), key: str(r.item_key), data: str(r.data) },
      deletedAt: num(r.deleted_at),
      updatedAt: num(r.updated_at) ?? 0,
    });
  }
  return { keyVersion: num(v.key_version), sealedKey, vaults, items };
}
