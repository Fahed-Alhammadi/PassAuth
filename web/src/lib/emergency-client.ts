/**
 * Emergency access requests and keys (`emergency.ts` has the rules, unit-tested). Confirming a contact makes an
 * emergency key for the access, after the user compared the contact's fingerprint with them: sealed to the contact,
 * wrapped by this account's key, and wrapping the key of each personal vault. Only vaults this app's own data says are
 * personal are ever wrapped, whatever the server lists.
 *
 * The roster (sealed with the account key, so the server keeps it but can't read or change it) lists the accesses this
 * account's apps may add wraps for, with the contact's key, name and email as the user confirmed them: confirming adds
 * the access to it first, removing takes it out first, and every write (and every fill) drops accesses the server no
 * longer lists, so one that ended can't be brought back. The fill (`fillEmergencyKeys`, after unlocking, a change to
 * the vaults and a replaced key) adds wraps only for accesses in it, and never acts on a roster older than the newest
 * this device opened, nor on one that doesn't open. Each device keeps its last trusted roster (sealed) to compare with.
 * Accesses that hold keys but aren't in the roster get "Confirm again" (`confirmAgain`).
 *
 * Removing a contact who held the key replaces the keys of the personal vaults they could open (only those). Viewing a
 * grantor's vaults opens the sealed key, then each wrapped vault key. Everything decrypted stays in memory (the page's
 * state) and every key handle is freed as soon as it has been used.
 */
import * as core from "../wasm/passauth_core";
import { ApiError, UnreachableError, api, friendlyError, hasErrorCode, hasFeature, knownPublicConfig, loadPublicConfig } from "./api";
import {
  EMPTY_ROSTER,
  KEY_VERSION,
  fillableAccesses,
  freshRoster,
  hasKeys,
  isPersonal,
  isRemoved,
  needsConfirmAgain,
  nextRoster,
  personName,
  pruneRoster,
  readGrant,
  readGrantorVault,
  readGrants,
  readRoster,
  removedText,
  restoredRosterForward,
  reviewRoster,
  rosterEntry,
  rosterIsOlder,
  rosterJson,
  sha256b64,
  vaultsToReKey,
  vaultsToWrap,
  type Grant,
  type GrantLists,
  type ReviewedEntry,
  type Roster,
  type RosterEntry,
} from "./emergency";
import { readMembers, type Item, type MemberRow } from "./types";
import { getAccount, getState, onVaultKeysChange, reauth, rotateVaultKeys, setEmergencyNotice, sync } from "./vault";

const LOCKED = "The vault is locked. Unlock it and try again.";
const UNEXPECTED = "The server sent an unexpected response. Try again.";
const SERVER_TOO_OLD = "Your PassAuth server needs an update before emergency contacts can be confirmed or their vaults viewed. Ask the server's admin.";
const APP_TOO_OLD = "This emergency access uses keys this version of PassAuth can't open. Update PassAuth, then try again.";
const VAULTS_CHANGED = "Your vaults changed while this was being saved. Try again.";
const NOT_OURS = "This access's key wasn't made by your account. Remove the contact, then name them again.";
/** The vault notice when the server's roster is older than one this device opened. */
export const ROSTER_ROLLED_BACK =
  "Your server sent an older list of emergency contacts, so PassAuth didn't change their access. Ask your server's admin.";
/** The vault notice when the server's roster can't be opened with this account's key. */
export const ROSTER_UNREADABLE =
  "Your server sent a list of emergency contacts that PassAuth can't open, so PassAuth didn't change their access. Ask your server's admin.";
const path = (id: string, rest = "") => `/emergency-access/${encodeURIComponent(id)}${rest}`;

function grantOf(value: unknown): Grant {
  const g = readGrant(value);
  if (!g) throw new Error(UNEXPECTED);
  return g;
}

export const listGrants = async (): Promise<GrantLists> => readGrants(await api("/emergency-access"));

/**
 * Throws unless the server gives contacts emergency keys (v2): an older one would store this app's sealed key as an
 * account key and hand out vault keys this app can't open.
 */
async function requireEmergencyKeys(): Promise<void> {
  const config = knownPublicConfig() ?? (await loadPublicConfig());
  if (!config) throw new UnreachableError();
  if (!hasFeature(config, "emergency_vault_keys")) throw new Error(SERVER_TOO_OLD);
}

/** Name a trusted contact (an account on this server with a verified email address). */
export async function inviteContact(email: string, waitDays: number): Promise<Grant> {
  try {
    return grantOf(await api("/emergency-access", { body: { grantee_email: email.trim(), wait_days: waitDays } }));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404)
      throw new Error("There's no account with that email address on this server, or it isn't verified yet. Your contact needs an account here first.");
    if (e instanceof ApiError && e.status === 409) throw new Error("This person is your emergency contact already.");
    throw e;
  }
}

// -------------------------------------------------------------- the roster

const seenKey = (userId: string) => `pa.roster.${userId}`;
const trustedKey = (userId: string) => `pa.roster-trusted.${userId}`;

/** The highest roster version this device has opened for the account (0: none). */
function seenVersion(): number {
  try {
    const n = Number(localStorage.getItem(seenKey(getState().userId)) ?? "0");
    return Number.isInteger(n) && n > 0 ? n : 0;
  } catch {
    return 0;
  }
}

/**
 * Remember a roster this device trusts: its version (the remembered one never goes down) and the sealed roster itself
 * (null: the server has none), the copy "Use the server's list" compares with.
 */
function rememberRoster(version: number, sealed: string | null) {
  const uid = getState().userId;
  if (version < seenVersion()) return;
  try {
    localStorage.setItem(seenKey(uid), String(version));
    if (sealed === null) localStorage.removeItem(trustedKey(uid));
    else localStorage.setItem(trustedKey(uid), sealed);
  } catch {
    /* storage unavailable: this device then can't tell a rolled-back roster */
  }
}

/** This device's last trusted roster, opened with the account's key; null when it keeps none (or it doesn't open). */
function trustedRoster(): Roster | null {
  const acct = getAccount();
  let sealed: string | null = null;
  try {
    sealed = localStorage.getItem(trustedKey(getState().userId));
  } catch {
    return null;
  }
  if (!acct || !sealed) return null;
  try {
    return readRoster(acct.openEmergencyRoster(sealed));
  } catch {
    return null;
  }
}

type OpenedRoster = { roster: Roster; seq: number; problem: null | "older" | "unreadable" };

/**
 * The account's roster from a listing, opened with its key: empty before any is stored. `problem` when it can't be
 * trusted: older than one this device opened, or not this account's. A device that remembers nothing trusts the first
 * roster it opens. A roster that can be trusted is remembered.
 */
function openRoster(lists: GrantLists): OpenedRoster {
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  const seq = lists.rosterSeq ?? 0;
  let roster: Roster | null = EMPTY_ROSTER;
  if (lists.roster !== null) {
    try {
      roster = readRoster(acct.openEmergencyRoster(lists.roster));
    } catch {
      roster = null;
    }
  }
  if (!roster) return { roster: EMPTY_ROSTER, seq, problem: "unreadable" };
  if (rosterIsOlder(roster, seenVersion())) return { roster, seq, problem: "older" };
  rememberRoster(roster.version, lists.roster);
  return { roster, seq, problem: null };
}

/** Seal `next` and store it with the compare-and-swap number `seq`, then remember it. */
async function writeRoster(next: Roster, seq: number): Promise<void> {
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  const sealed = acct.sealEmergencyRoster(rosterJson(next));
  await api("/emergency-access/roster", { method: "PUT", body: { roster: sealed, seq } });
  rememberRoster(next.version, sealed);
}

const listedIds = (lists: GrantLists) => new Set(lists.asGrantor.map((g) => g.id));

/**
 * Store the roster with one access added or taken out (null: only the cleanup), and without the accesses the server no
 * longer lists: read, changed and stored with the next sequence number, once more when another device changed it
 * meanwhile (409 `roster_changed`). A roster this device can't trust is never the base of a new one (that would bring
 * back what it no longer lists): adding then stops with its notice; the rest leaves it alone (this device adds no wraps
 * while it can't trust the roster, and removed accesses go on the server).
 */
async function changeRoster(change: { add: RosterEntry } | { remove: string; hash?: string } | null): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    const lists = await listGrants();
    const opened = openRoster(lists);
    if (opened.problem) {
      setEmergencyNotice(opened.problem === "older" ? ROSTER_ROLLED_BACK : ROSTER_UNREADABLE);
      if (change && "add" in change) throw new Error(opened.problem === "older" ? ROSTER_ROLLED_BACK : ROSTER_UNREADABLE);
      return;
    }
    if (change && "add" in change && isRemoved(opened.roster, change.add.id, change.add.grantorKeyHash)) throw new Error(removedText("This contact"));
    const next = nextRoster(opened.roster, seenVersion(), change, listedIds(lists));
    if (!next) return;
    try {
      await writeRoster(next, opened.seq + 1);
      return;
    } catch (e) {
      if (attempt > 0 || !hasErrorCode(e, "roster_changed")) throw e;
    }
  }
}

/** The roster as the Emergency page needs it: the problem, if any, and else what it says about each access. */
export interface RosterState {
  problem: null | "older" | "unreadable";
  /** The trusted roster; null while there is a problem. */
  roster: Roster | null;
  /** Accesses holding keys that the roster doesn't list (and didn't remove): "Confirm again". */
  confirmAgain: Set<string>;
  /** Accesses the roster removed (by id or by their key): never confirmed again, only added as new contacts. */
  removed: Set<string>;
}

export async function rosterState(): Promise<RosterState> {
  const none = { roster: null, confirmAgain: new Set<string>(), removed: new Set<string>() };
  if (!getAccount()) return { problem: null, ...none };
  const lists = await listGrants();
  const opened = openRoster(lists);
  if (opened.problem) return { problem: opened.problem, ...none };
  const confirmAgain = new Set<string>();
  const removed = new Set<string>();
  for (const g of lists.asGrantor) {
    const hash = g.grantorKey ? await sha256b64(g.grantorKey) : null;
    if (isRemoved(opened.roster, g.id, hash)) removed.add(g.id);
    else if (needsConfirmAgain(g, opened.roster, hash)) confirmAgain.add(g.id);
  }
  return { problem: null, roster: opened.roster, confirmAgain, removed };
}

/** The server's roster for review before "Use the server's list". */
export interface ServerRoster {
  /** The roster as it opened under the account's key; null when the server has none at all. */
  roster: Roster | null;
  /**
   * Its entries for accesses the server lists, with the names, emails and keys from inside the roster (never the
   * server's listing), each marked when this device's last trusted roster doesn't have it.
   */
  entries: ReviewedEntry[];
}

/**
 * The server's roster, opened with the account's key, for the user to review when this device has seen a newer one
 * (after a server restore). Throws when it doesn't open: such a roster is never taken.
 */
export async function loadServerRoster(): Promise<ServerRoster> {
  const lists = await listGrants();
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  if (lists.roster === null) return { roster: null, entries: [] };
  let roster: Roster | null = null;
  try {
    roster = readRoster(acct.openEmergencyRoster(lists.roster));
  } catch {
    /* refused below */
  }
  if (!roster) throw new Error(ROSTER_UNREADABLE);
  return { roster, entries: reviewRoster(roster, trustedRoster(), listedIds(lists)) };
}

/** The server's roster changed between the review and "Use the server's list": read it again and show it again. */
export class RosterChangedError extends Error {
  constructor() {
    super("Your server's list of emergency contacts changed meanwhile. Check it again before you continue.");
  }
}

/**
 * "Use the server's list" (after the server's admin restored a backup), with the master password (`password`, checked
 * through a reauth as approving is): the roster the user reviewed (`reviewed`) is read and opened again, then written
 * forward: its entries for accesses the server lists, as a new roster one version above the newest this device saw,
 * stored with the usual compare-and-swap and then remembered, so every older version, the ones in between included,
 * stays refused. With no roster on the server, that is an empty one. A roster that doesn't open is refused; one that
 * changed since the review (or a write that loses the compare-and-swap) throws `RosterChangedError`, never writing what
 * wasn't reviewed.
 */
export async function useServerRoster(reviewed: ServerRoster, password: string): Promise<void> {
  await reauth(password);
  const lists = await listGrants();
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  let current: Roster | null = EMPTY_ROSTER;
  if (lists.roster !== null) {
    try {
      current = readRoster(acct.openEmergencyRoster(lists.roster));
    } catch {
      current = null;
    }
    if (!current) throw new Error(ROSTER_UNREADABLE);
  }
  const same = reviewed.roster === null ? lists.roster === null : lists.roster !== null && rosterJson(reviewed.roster) === rosterJson(current);
  if (!same) throw new RosterChangedError();
  // Exactly what was shown (less what was removed or ended since): never an entry the user didn't see.
  const next = restoredRosterForward(reviewed.entries, current, trustedRoster(), seenVersion(), listedIds(lists));
  try {
    await writeRoster(next, (lists.rosterSeq ?? 0) + 1);
  } catch (e) {
    throw hasErrorCode(e, "roster_changed") ? new RosterChangedError() : e;
  }
  setEmergencyNotice(null);
  void fillEmergencyKeys().catch(() => {});
}

/**
 * "Start a new list", with the master password (`password`), when the server's roster doesn't open with the account's
 * key (garbage written by a stolen session or the server): an empty roster above the newest this device saw. Contacts
 * who hold keys then show "Confirm again".
 */
export async function startNewRoster(password: string): Promise<void> {
  await reauth(password);
  const lists = await listGrants();
  if (openRoster(lists).problem !== "unreadable") throw new Error("Your server's list of emergency contacts opens again. Reload the page.");
  try {
    // The contacts this device knows were removed stay removed.
    await writeRoster(freshRoster(seenVersion(), trustedRoster()), (lists.rosterSeq ?? 0) + 1);
  } catch (e) {
    throw hasErrorCode(e, "roster_changed") ? new Error("Your list of emergency contacts changed on another device just now. Try again.") : e;
  }
  setEmergencyNotice(null);
}

// ---------------------------------------------------------------- the keys

/**
 * Of the vaults the server names, the ones this app's own data says are personal: the latest sync shows the account as
 * their owner with its own key, and their members list holds this account alone (one request per vault).
 */
async function personalOf(wanted: readonly string[]): Promise<{ wrap: string[]; refused: string[] }> {
  const me = getState().userId;
  const own = (id: string) => getState().vaults.find((v) => v.id === id);
  const members = new Map<string, MemberRow[] | null>();
  for (const id of new Set(wanted)) {
    const v = own(id);
    if (!v || v.role !== "owner" || v.kind !== "account") continue;
    try {
      members.set(id, readMembers(await api(`/vaults/${encodeURIComponent(id)}/members`)));
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 404)) throw e;
    }
  }
  return vaultsToWrap(wanted, (id) => isPersonal(own(id), members.get(id), me));
}

/**
 * Each vault's key wrapped with `key` (for its access), with the epoch of the key wrapped. Synchronous: the vault key
 * handles are looked up now and never held across an await.
 */
function wrapVaults(key: core.EmergencyKey, vaultIds: readonly string[]) {
  return vaultIds.map((id) => {
    const v = getState().vaults.find((x) => x.id === id);
    if (!v || v.epoch === undefined) throw new Error(VAULTS_CHANGED);
    return { vault_id: id, wrapped_key: key.wrapVaultKey(v.key, id), key_epoch: v.epoch };
  });
}

/** The server's answer when the wraps sent no longer fit (a vault shared, created or re-keyed meanwhile): try once more. */
const vaultsMoved = (e: unknown) => hasErrorCode(e, "emergency_vaults_changed") || hasErrorCode(e, "vault_key_changed");

/** Access `id` as the server lists it now (the grantor's side). */
async function currentAccess(id: string): Promise<Grant> {
  const g = (await listGrants()).asGrantor.find((x) => x.id === id);
  if (!g) throw new Error("This emergency contact is no longer on your server's list. Reload the page.");
  return g;
}

/**
 * The grantor's step after the contact accepted (`g` as the user checked it, fingerprint included): a new emergency key
 * for the access, put into the roster (with the contact's key, name and email as checked, and the key's `grantor_key`
 * by hash) before the server gets anything of it, then sealed to the contact's public key, wrapped by this account's
 * key, and wrapping every personal vault's key. When the vaults changed meanwhile, the access is read again and
 * confirmed once more with the same key. When the access already holds a key (an earlier try landed and its answer got
 * lost, or another of the account's apps confirmed it), no new key is made: the roster points at that one
 * (`confirmAgain`), with the contact key checked here.
 */
export async function confirmContact(g: Grant): Promise<Grant> {
  await requireEmergencyKeys();
  const who = personName(g.grantee);
  if (!g.grantee.publicKey) throw new Error(`${who}'s account has no key to confirm. Ask them to sign in once, then try again.`);
  const keyChanged = () => new Error(`${who}'s key changed. Check their fingerprint again before you confirm them.`);
  const lists = await listGrants();
  const fresh = lists.asGrantor.find((x) => x.id === g.id);
  if (!fresh) throw new Error("This emergency contact is no longer on your server's list. Reload the page.");
  if (fresh.grantee.publicKey !== g.grantee.publicKey) throw keyChanged();
  const opened = openRoster(lists);
  if (!opened.problem && isRemoved(opened.roster, g.id, fresh.grantorKey ? await sha256b64(fresh.grantorKey) : null)) throw new Error(removedText(who));
  if (hasKeys(fresh)) {
    await confirmAgain(g);
    return currentAccess(g.id);
  }
  if (fresh.status !== "accepted") throw new Error(VAULTS_CHANGED);
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  const made = acct.newEmergencyKey(g.id);
  try {
    const key = made.takeKey();
    try {
      // This account's id as the server names it, and the contact's key the user checked (the core refuses others).
      const sealed = key.sealFor(g.grantee.publicKey, g.grantor.id, g.id);
      await changeRoster({ add: rosterEntry(g, g.grantee.publicKey, await sha256b64(made.wrapped)) });
      let current = fresh;
      for (let attempt = 0; ; attempt++) {
        const { wrap, refused } = await personalOf(current.missingVaults);
        if (refused.length)
          throw new Error(
            "PassAuth couldn't check that every vault your server lists as personal is yours alone (one may be shared, or couldn't be opened here), so nothing was confirmed. Reload the page and try again.",
          );
        const body = { sealed_key: sealed, grantor_key: made.wrapped, vault_keys: wrapVaults(key, wrap) };
        try {
          return grantOf(await api(path(g.id, "/confirm"), { body }));
        } catch (e) {
          if (attempt === 0 && vaultsMoved(e)) {
            await sync();
            const again = await currentAccess(g.id);
            if (again.grantee.publicKey !== g.grantee.publicKey) throw keyChanged();
            if (again.status === "accepted") {
              current = again;
              continue;
            }
          }
          // The access holds a key now (this try's answer was lost, or another app confirmed first): use that one.
          const now = await currentAccess(g.id).catch(() => null);
          if (now && hasKeys(now) && now.grantee.publicKey === g.grantee.publicKey) {
            await confirmAgain(g);
            return now;
          }
          throw e;
        }
      }
    } finally {
      key.free();
    }
  } finally {
    made.free();
  }
}

/**
 * "Confirm again": put an access that holds keys back into the roster (after it was dropped while the server didn't
 * list it, a write that got lost, or "Start a new list"), once the user checked the contact's fingerprint (`checked`:
 * the access as the user saw it). No new key is made: the access's own `grantor_key`, read again now, must open under
 * this account's key for this access, and the entry takes its hash with the contact key, name and email checked.
 */
export async function confirmAgain(checked: Grant): Promise<void> {
  await requireEmergencyKeys();
  const who = personName(checked.grantee);
  const now = await currentAccess(checked.id);
  if (!checked.grantee.publicKey || now.grantee.publicKey !== checked.grantee.publicKey)
    throw new Error(`${who}'s key changed. Check their fingerprint again before you confirm them.`);
  if (!hasKeys(now) || !now.grantorKey) throw new Error(VAULTS_CHANGED);
  const hash = await sha256b64(now.grantorKey);
  const opened = openRoster(await listGrants());
  if (!opened.problem && isRemoved(opened.roster, now.id, hash)) throw new Error(removedText(who));
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  try {
    acct.openEmergencyKey(now.id, now.grantorKey).free();
  } catch {
    throw new Error(NOT_OURS);
  }
  await changeRoster({ add: rosterEntry(checked, checked.grantee.publicKey, hash) });
  void fillEmergencyKeys().catch(() => {});
}

/**
 * Add the wraps the server says are missing (`missing_vaults`) for the accesses the roster lists: personal vaults that
 * have none (a new vault, one no longer shared, a replaced key). Runs after unlocking, a change to the vaults and
 * replacing vault keys (`onVaultKeysChange`); one run at a time, and one more when asked again meanwhile. A roster this
 * device can't trust stops it, with a vault notice; a trusted one first loses the accesses the server no longer lists.
 * Vaults this app doesn't see as personal are left out; wraps the server refuses wait for the next run.
 */
export function fillEmergencyKeys(): Promise<void> {
  if (filling) {
    fillAgain = true;
    return filling;
  }
  filling = (async () => {
    try {
      do {
        fillAgain = false;
        await fillOnce();
      } while (fillAgain);
    } finally {
      filling = null;
    }
  })();
  return filling;
}

let filling: Promise<void> | null = null;
let fillAgain = false;

async function fillOnce() {
  const config = knownPublicConfig() ?? (await loadPublicConfig());
  if (!hasFeature(config, "emergency_access") || !hasFeature(config, "emergency_vault_keys")) return;
  if (getState().status !== "unlocked") return;
  const lists = await listGrants();
  const opened = openRoster(lists);
  if (opened.problem) {
    setEmergencyNotice(opened.problem === "older" ? ROSTER_ROLLED_BACK : ROSTER_UNREADABLE);
    return;
  }
  setEmergencyNotice(null);
  // Accesses that ended (by either side, or with an account) leave the roster for good: a server that lists one again
  // later, with its old key, gets nothing for it.
  let roster = opened.roster;
  const listed = listedIds(lists);
  if (pruneRoster(roster, listed).length < roster.accesses.length) {
    roster = { ...roster, accesses: pruneRoster(roster, listed) };
    await changeRoster(null).catch(() => {});
  }
  const hashes = new Map<string, string>();
  for (const g of lists.asGrantor) if (g.grantorKey) hashes.set(g.grantorKey, await sha256b64(g.grantorKey));
  const todo = fillableAccesses(lists.asGrantor, roster, hashes);
  if (!todo.length) return;
  const { wrap } = await personalOf(todo.flatMap((g) => g.missingVaults));
  const personal = new Set(wrap);
  for (const g of todo) {
    const vaults = g.missingVaults.filter((id) => personal.has(id));
    const acct = getAccount();
    if (!vaults.length || !g.grantorKey || !acct) continue;
    let key: core.EmergencyKey;
    try {
      key = acct.openEmergencyKey(g.id, g.grantorKey);
    } catch {
      // Not this account's key for this access: nothing this app can add.
      continue;
    }
    let vaultKeys: ReturnType<typeof wrapVaults>;
    try {
      vaultKeys = wrapVaults(key, vaults);
    } finally {
      key.free();
    }
    try {
      await api(path(g.id, "/vault-keys"), { method: "PUT", body: { vault_keys: vaultKeys } });
    } catch (e) {
      if (!vaultsMoved(e)) throw e;
    }
  }
}

// The vault runs it after unlocking, a change to the vaults and replacing vault keys. Installed when this module loads:
// the app imports it with the emergency pages, in the web vault and the desktop app alike.
onVaultKeysChange(fillEmergencyKeys);

/** A reauth token for `password` (the master password), as the server wants for approving and shortening the wait. */
const reauthHeader = async (password: string) => ({ "x-reauth-token": await reauth(password) });

/** Change the waiting period; a shorter one needs the master password (`password`). */
export const changeWait = async (id: string, waitDays: number, password?: string) =>
  grantOf(await api(path(id), { method: "PUT", body: { wait_days: waitDays }, headers: password ? await reauthHeader(password) : undefined }));
export const acceptGrant = async (id: string) => grantOf(await api(path(id, "/accept"), { method: "POST" }));
export const requestAccess = async (id: string) => grantOf(await api(path(id, "/request"), { method: "POST" }));
/** Approve a request now; needs the master password. */
export const approveGrant = async (id: string, password: string) => grantOf(await api(path(id, "/approve"), { method: "POST", headers: await reauthHeader(password) }));
export const rejectGrant = async (id: string) => grantOf(await api(path(id, "/reject"), { method: "POST" }));

/** What removing a contact did about vault keys: how many were replaced, and why the rest wasn't (null: all done). */
export interface Removal {
  rotated: number;
  failed: string | null;
}

/**
 * The grantor removes contact `g`: out of the roster first (no app of the account adds wraps for it again, whatever the
 * server sends), then the access. When the contact held the key, the server asks for new keys of the vaults they could
 * open: those this app sees as personal are replaced now (the server keeps asking for any that fail, and the vault
 * notices say so). Already gone counts as done.
 */
export async function removeContact(g: Grant): Promise<Removal> {
  // Out of the roster for good, by id and by the key it holds (if any): no app of the account gives it keys again.
  await changeRoster({ remove: g.id, ...(g.grantorKey ? { hash: await sha256b64(g.grantorKey) } : {}) });
  let answer: unknown;
  try {
    answer = await api(path(g.id), { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
    return { rotated: 0, failed: null };
  }
  const named = vaultsToReKey(answer, () => true);
  if (!named.length) return { rotated: 0, failed: null };
  try {
    const { wrap } = await personalOf(named);
    const vaults = vaultsToReKey(answer, (id) => wrap.includes(id));
    if (vaults.length) await rotateVaultKeys(vaults);
    return { rotated: vaults.length, failed: null };
  } catch (e) {
    return { rotated: 0, failed: friendlyError(e) };
  }
}

/** The contact steps down or declines (never replaces anyone's keys). Already gone counts as done. */
export async function leaveGrant(id: string): Promise<void> {
  try {
    await api(path(id), { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
}

// ------------------------------------------------------------- the vault

export interface GrantorEntry {
  id: string;
  vaultId: string;
  item: Item;
  deletedAt: number | null;
}

/** A grantor's vaults, decrypted for viewing: memory only. */
export interface GrantorVault {
  grant: Grant;
  vaults: { id: string; name: string }[];
  items: GrantorEntry[];
  /** Items (and vaults' items) that couldn't be decrypted. */
  failed: number;
}

/**
 * Fetch and decrypt the personal vaults a grantor shared through emergency access (approved accesses only). The sealed
 * emergency key is opened for this, each vault key is used for its items and freed, and the emergency key is freed at
 * the end.
 */
export async function openGrantorVault(id: string): Promise<GrantorVault> {
  await requireEmergencyKeys();
  const answer = await api(path(id, "/vault"));
  const data = readGrantorVault(answer);
  const grant = readGrant((answer as { grant?: unknown } | null)?.grant);
  if (!data || !grant || grant.id !== id) throw new Error(UNEXPECTED);
  if (data.keyVersion !== KEY_VERSION) throw new Error(data.keyVersion === null ? SERVER_TOO_OLD : APP_TOO_OLD);
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  let key: core.EmergencyKey;
  try {
    key = acct.openSealedEmergencyKey(grant.grantor.id, id, data.sealedKey);
  } catch {
    throw new Error(
      `Your account's keys can't open the access ${personName(grant.grantor)} gave you. Ask them to remove you as their emergency contact and name you again.`,
    );
  }
  const vaults: GrantorVault["vaults"] = [];
  const items: GrantorEntry[] = [];
  let failed = 0;
  try {
    for (const v of data.vaults) {
      const rows = data.items.filter((r) => r.row.vault_id === v.id);
      let vaultKey: core.VaultKey;
      try {
        vaultKey = key.openVaultKey(v.id, v.wrappedKey);
      } catch {
        failed += rows.length;
        continue;
      }
      try {
        let name = "Vault";
        try {
          const meta = vaultKey.decryptMeta(v.id, v.meta) as { name?: unknown } | null;
          if (typeof meta?.name === "string" && meta.name.trim()) name = meta.name;
        } catch {
          /* keep the generic name */
        }
        vaults.push({ id: v.id, name });
        for (const r of rows) {
          try {
            items.push({ id: r.row.id, vaultId: v.id, item: vaultKey.decryptItem(r.row) as Item, deletedAt: r.deletedAt });
          } catch {
            failed++;
          }
        }
      } finally {
        vaultKey.free();
      }
    }
  } finally {
    key.free();
  }
  const byName = new Intl.Collator(undefined, { sensitivity: "base" });
  items.sort((a, b) => byName.compare(a.item.name, b.item.name));
  return { grant, vaults, items, failed };
}
