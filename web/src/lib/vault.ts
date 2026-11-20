/**
 * Vault session: authentication flows, key handles and the decrypted vault.
 * Decrypted data and key handles live only in memory; locking frees them.
 *
 * Key handles are WASM objects that `sync()` frees when it replaces them, so code must
 * never hold a `VaultKey` across an `await`: look it up again with `vaultFor()` instead.
 *
 * Writes encrypted with a vault key send that key's epoch (`key_epoch`, from /sync). A server whose key is newer
 * refuses them (409 vault_key_changed, nothing written): the write syncs, encrypts again with the new key and is
 * sent once more; a key replacement (rotate, remove member) instead asks the user to try again.
 *
 * Delta sync (servers with the `delta_sync` feature; rules in `delta.ts`): the encrypted rows of the last /sync
 * answer are kept with its cursor, later syncs ask only for what changed since, and decrypted items are reused while
 * their ciphertext and vault key stay the same. Without the feature every sync fetches the whole account, as before.
 *
 * Invitations (servers with `vault_invitations`; `invitations.ts`): every /sync lists the vaults shared with the account
 * and not accepted yet. Their sealed keys are opened only to read the vault's name, then freed; accepting makes the vault
 * a membership and it arrives whole with the next sync.
 *
 * Signed sharing (servers with `signed_sharing`; `signed-sharing.ts`): every sync first checks every vault row and
 * invitation (member roster chain, key commitment, key epoch pins, share signature against the signer's pinned
 * identity, admission); a vault that fails is never opened and is listed in `State.blockedVaults` instead, and a sealed
 * vault the account never accepted waits in `State.consents`. The checks are sticky once the server showed it signs
 * (its config lists the feature, or this device saw signed state for the account); while the server's features are
 * unknown they run without writing anything sticky. Sharing, key replacement and re-signing are signed, after a member
 * review the user confirms when the vault has no trusted roster yet or people are missing. A server that doesn't list
 * the feature (or answers that it doesn't sign) is refused: nothing of its /sync is used (`SERVER_UPDATE_NEEDED`).
 *
 * Vault manifests (servers with `vault_manifest`; `manifest.ts`): before a /sync answer is taken over, each opened
 * vault's whole item set is checked against the vault's sealed manifest and the manifest this device remembers (its
 * version and link; a manifest further ahead must lead back to it through the vault's manifest log). No answer is ever
 * shown or kept unchecked (`doSync`). A vault that doesn't check
 * out stays readable with a warning (`Vault.manifestWarning`) and takes no writes until "Use the server's copy"
 * (`acceptServerCopy`): when the served copy is consistent in itself any member accepts it on this device alone,
 * otherwise a member with write access stores a new record over it. A row that doesn't open never changes a vault's
 * verdict or holds its writes: the copy this session already opened is kept when only the served key fails, an item
 * from a newer app is listed as such (an owner or admin may delete it for good), and anything else is listed with a notice and may be deleted for good by
 * someone who can edit (`purgeUnopenable`); nothing tells the user to. An answer with a lower revision than the one
 * shown is judged, not ignored, unless it can be a race (`fetchSync`). Every write into a vault with a manifest carries the next one
 * (`manifestFor`); when the vault changed meanwhile (409 `manifest_conflict`) the write syncs, checks and is sent again,
 * at most three times. After a sync this app also starts a vault's first manifest once every member's apps keep them,
 * and deletes trashed items that are due (the server's sweeper leaves vaults with a manifest alone).
 *
 * Emergency access (`emergency-client.ts`) wraps the keys of the account's personal vaults for its emergency contacts.
 * After anything that can leave a personal vault without those wraps (unlocking, a new vault, a replaced key), the hook
 * set with `onVaultKeysChange` runs once the vault shows the change.
 */
import { useSyncExternalStore } from "react";
import * as core from "../wasm/passauth_core";
import {
  ApiError,
  UnreachableError,
  api,
  deviceInfo,
  friendlyError,
  getTokens,
  hasErrorCode,
  hasFeature,
  isOutOfStorage,
  knownPublicConfig,
  loadPublicConfig,
  onSessionLost,
  onTwoStepRequired,
  refreshPublicConfig,
  SERVER_UPDATE_NEEDED,
  serverTooOld,
  setTokens,
  type PublicConfig,
} from "./api";
import { stripAttachments } from "./attachments";
import { avatars } from "./avatar";
import { afterTwoStepSetup, isTwoStepClose, isTwoStepNotice, readPolicies, readViolations, type Violation } from "./policies";
import { checkCode, secretKeyToKeep, type CodeOutcome } from "./device-login";
import { afterWrite, applyOwnManifest, applyOwnWrite, knownSeq, mergeSync, noticeAction, sameCiphertext, vaultKeyChanged, type Merged, type OwnWrite, type Snapshot, type SyncNotice } from "./delta";
import { readVersion, readVersions, restoredItem, type ItemVersion } from "./history";
import { openInvitations, type Invitation } from "./invitations";
import { ROLLBACK_KEPT, ROLLBACK_SHOWN, RevMemory, revOf } from "./item-revs";
import {
  ACCEPT_NO_ANSWER,
  MANIFEST_BUSY,
  MANIFEST_HELD,
  MANIFEST_NOT_READY,
  MANIFEST_TRIES,
  MANIFEST_UNCHECKED,
  NEWER_ITEM_NOTE,
  NEWER_ITEMS_REKEY,
  isNewerItemError,
  ManifestMemory,
  TrashSeen,
  UNREADABLE_READS,
  VAULT_WARNING_READER,
  acceptVault,
  acceptable,
  baselineSeq,
  checkApplies,
  dueTrash,
  linkStored,
  manifestQuery,
  manifestRaced,
  manifestRow,
  manifestSeq,
  mayPurge,
  mayStart,
  nextEntry,
  rowLink,
  startEntry,
  unresolved,
  verifyVault,
  wireEntry,
  withQuery,
  type ManifestEntry,
  type ManifestRow,
  type ManifestStatus,
} from "./manifest";
import * as signed from "./signed-sharing";
import { RaceError, ReviewNeededError, type Confirmation, type Consent, type InvitationTrust, type KeyChange, type ReviewView, type VaultTrust, type Verdicts } from "./signed-sharing";
import {
  ACCOUNT_MISMATCH,
  ASK_OWNER_TO_SIGN,
  KEY_REPLACEMENTS_LIMIT,
  MEMBERS_SIGNED_UPDATE,
  cleanText,
  identityOf,
  membersDifferText,
  namesFromRows,
  readIdentity,
  readMemberDiff,
  readMembersAnswer,
  type MembersAnswer,
  type PublicIdentity,
  type SignedMemberRow,
} from "./signing";
import {
  DELETED_TEXT,
  MOVED_TEXT,
  LIST_DROPPED,
  LIST_UNREADABLE,
  OfflineChangeError,
  CONFLICT_TEXT,
  HAS_CHANGE,
  MAX_TRIES,
  NEEDS_CONNECTION,
  changeFor,
  classifyFailure,
  conflictKind,
  decideSend,
  emptyList,
  holdReason,
  mergeChange,
  overlay,
  parseList,
  removeChange,
  replaceChange,
  resolveConflict,
  serializeList,
  waitsAfter,
  type ChangeList,
  type ConflictKind,
  type Failure,
  type NewChange,
  type OfflineChange,
  type Resolution,
  type SentBody,
  type ServerRow,
} from "./offline-changes";
import { getDesktop, secretStore } from "./platform";
import { server } from "./server";
import { encryptedSizeBound } from "./sizes";
import { getCredential } from "./webauthn";
import {
  UNEXPECTED_RESPONSE,
  expectStrings,
  isSyncResponse,
  readFoundUser,
  readLoginFinish,
  readMembers,
  readPrelogin,
  type Bundle,
  type EncryptedItem,
  type Item,
  type KeyKind,
  type LoginFinishResponse,
  type Role,
  type SyncItemRow,
  type SyncVaultRow,
  type VaultEntry,
} from "./types";

/**
 * "two-step": the server requires two-step login (policy) and the account has no method yet, so it refuses everything
 * but setting one up and signing out. The account keys stay in memory when the screen came up at sign-in, unlock or
 * while the vault was open (`holdsKeys()`), so the vault opens as soon as a method is set up.
 */
export type Status = "loading" | "unreachable" | "logged-out" | "locked" | "unlocked" | "two-step";

export interface Vault {
  id: string;
  name: string;
  role: Role;
  kind: KeyKind;
  key: core.VaultKey;
  /** Epoch of `key` (from the same /sync); undefined with servers that don't have key epochs. */
  epoch?: number;
  /** Signed sharing: how the key is vouched for ("Not yet signed" for shares from before); undefined without the feature. */
  trust?: VaultTrust;
  /** Signed sharing: the vault's member roster version (0: none yet, so its owners and admins are asked to sign it). */
  rosterSeq: number;
  /**
   * Vault manifests: the server's copy of this vault doesn't match its record of changes (or the record went back). The
   * vault stays readable, shows `VAULT_WARNING` and takes no writes until `acceptServerCopy`, or a later sync that checks out.
   */
  manifestWarning?: boolean;
  /**
   * With `manifestWarning`: the server's copy is consistent in itself (its record matches its items, or it shows no
   * record), so `acceptServerCopy` clears the warning on this device alone, without writing anything. Everyone gets
   * the action then, members who can only read too. Without it only someone who can edit can accept (a new record).
   */
  manifestAcceptable?: boolean;
  /**
   * With `manifestWarning` and `manifestAcceptable`: the server shows no record for this vault although this device
   * remembers one. Accepting forgets that memory, so the vault is no longer checked until a new record is started:
   * the confirmation says so (`USE_SERVER_COPY_NO_RECORD_BODY`, `acceptServerCopy`'s `noRecord`).
   */
  manifestNoRecord?: boolean;
  /**
   * The vault (checked: it has a record, or a warning) holds an item its key can't open (`State.unopenable`, kind
   * "unopenable"). `VAULT_UNOPENABLE` is shown as a notice of its own. It is no warning: the vault takes writes when
   * its record checks out, and nothing says to delete the item. Independent of `manifestWarning`.
   */
  manifestUnopenable?: boolean;
  /**
   * The user accepted "no record" for this vault on this device and it has none since: nothing is checked for it
   * (`VAULT_NOT_CHECKED`, a quiet note) until a record is started again.
   */
  manifestNotChecked?: boolean;
}

/**
 * A row of an opened vault that isn't shown as an item:
 * - "unopenable": it doesn't decrypt (and this device holds no copy of it that it opened before). Listed as "Item
 *   that can't be opened", with "Delete for good" for members who can edit.
 * - "newer": it decrypts, but holds an item this app can't read (a type or format from a later release). Listed as
 *   "Item from a newer version of PassAuth" with "Update PassAuth to see this item."; "Delete for good" only for the
 *   vault's owners and admins.
 */
export interface UnopenableItem {
  id: string;
  vaultId: string;
  /** Not null: the row is in the trash. */
  deletedAt: number | null;
  /** Whether this account can delete it now (`purgeUnopenable`): it may edit the vault, and the vault's record checks out. */
  deletable: boolean;
  kind: "unopenable" | "newer";
  /** The item's last known name, when this device still holds an earlier copy of it (memory only). */
  name?: string;
}

/** A vault signed sharing refused: never opened, filled from, saved to or shown (only this notice). */
export interface BlockedVault {
  id: string;
  role: Role;
  reason: string;
  /** Someone whose keys changed: the vault can be used again once the user trusts their new key. */
  changed?: KeyChange;
}

/**
 * A sealed vault the server lists for the account that it never accepted (signed sharing): never opened beyond its name,
 * shown like an invitation. Accepting needs a signed one; declining leaves it for good.
 */
export interface ConsentVault {
  id: string;
  role: Role;
  /** The vault's name (cleaned); null when it can't be read. */
  name: string | null;
  consent: Consent;
}

export interface State {
  status: Status;
  email: string;
  userId: string;
  name: string;
  emailVerified: boolean;
  vaults: Vault[];
  items: VaultEntry[];
  revision: number;
  warnings: string[];
  /** Vaults whose key still has to be replaced after a member was removed. */
  pendingRotations: string[];
  /** Vaults shared with the account and waiting for it to accept or decline (empty while locked). */
  invitations: Invitation[];
  /** What the account still has to change for the server's policies (`GET /account`, read after sign-in and unlock). */
  policyViolations: Violation[];
  /** Emergency access: why PassAuth left the contacts' keys alone (the server's list of them looked rolled back). */
  emergencyNotice: string | null;
  /** Signed sharing: vaults that failed their check (empty while locked or without the feature). */
  blockedVaults: BlockedVault[];
  /** Signed sharing: sealed vaults the server lists that the account never accepted (Accept / Decline, like invitations). */
  consents: ConsentVault[];
  /** Signed sharing: people whose keys changed since this account pinned them (from vaults and invitations). */
  keyChanges: KeyChange[];
  /** Signed sharing: sharing paused on this device, or the server's list of known keys looked rolled back. */
  signingNotice: string | null;
  /** Rows of opened vaults that aren't shown as items (listed in their vault, or in the trash): they don't decrypt, or hold an item from a newer app. */
  unopenable: UnopenableItem[];
  /**
   * This device's record of the vaults' manifests couldn't be read several times in a row (`MEMORY_UNREADABLE` with
   * "Reset on this device", `resetDeviceRecord`). Until then vaults that have a manifest take no writes.
   */
  deviceRecordUnreadable: boolean;
  /**
   * The server answered, but it is too old for this app (`SERVER_UPDATE_NEEDED`): at start-up nothing was loaded
   * (status "unreachable"); in an open vault syncing stopped and what is shown stays, with a notice.
   */
  serverOutdated: boolean;
  /**
   * Offline changes (desktop app only; ARCHITECTURE "Offline changes"): this account's changes that wait to be sent,
   * oldest first. `items` already shows them; this is for markers, the sync status and decisions. Empty while locked.
   */
  offlineChanges: OfflineChange[];
  /**
   * About the stored list itself: it can't be read (nothing is written over it then), or it didn't open for this
   * account and was removed. Null otherwise.
   */
  offlineNotice: string | null;
}

const initial: State = {
  status: "loading",
  email: "",
  userId: "",
  name: "",
  emailVerified: true,
  vaults: [],
  items: [],
  revision: 0,
  warnings: [],
  pendingRotations: [],
  invitations: [],
  policyViolations: [],
  emergencyNotice: null,
  blockedVaults: [],
  consents: [],
  keyChanges: [],
  signingNotice: null,
  unopenable: [],
  deviceRecordUnreadable: false,
  serverOutdated: false,
  offlineChanges: [],
  offlineNotice: null,
};
let state: State = initial;
let account: core.Account | null = null;
let bundle: Bundle | null = null;
let socket: WebSocket | null = null;
/** The session's live-sync origin from the socket's `hello` (shared by every tab and window of this session). */
let liveOrigin: string | null = null;
/** Bumped whenever the keys are dropped (lock, sign-out): async work started before that is discarded. */
let generation = 0;
/** Rows per vault that aren't shown as items in the copy held (they don't decrypt, or hold an item this app can't read): a key replacement needs every item. */
let undecryptable = new Map<string, number>();
/** Of those, the rows per vault that don't decrypt at all: a first manifest is never started over them. */
let unopenableRows = new Map<string, number>();
/** Ids of the rows held that decrypt but hold an item this app can't read (never deleted from here). */
let newerRows = new Set<string>();
/**
 * The encrypted rows of the last /sync answer, with its cursor on servers with delta sync (null otherwise). Memory only,
 * like the rest: kept while locked (the answer `boot()` fetched for the bundle, so unlocking asks only for what changed
 * since), dropped on sign-out and at sign-in.
 */
let synced: Snapshot | null = null;
/** Whether the last sync used delta sync (live-sync messages are then judged by vault numbers). */
let deltaOn = false;
/** The next sync fetches the whole account (no cursor) once: a vault's check needs every row afresh. */
let fullNext = false;
/** Vault manifests: each vault's verdict for the sync answer the copy came from (`manifest.ts`); absent: "none". */
let manifestStatus = new Map<string, ManifestStatus>();
/**
 * Vaults whose check couldn't be finished (the manifest log couldn't be fetched, or this device's memory can't be
 * read): no warning, and writes into them wait for a sync that checks them.
 */
let unchecked = new Set<string>();
/** Unresolved vaults whose served copy is consistent in itself: accepting it needs no write (`acceptVault`). */
let acceptableVaults = new Set<string>();
/** Of those, the vaults the server shows without any record: accepting forgets this device's memory of them. */
let noRecordVaults = new Set<string>();
/**
 * Counts every own write this app showed without asking the server (the copy moved, and the device memory with it).
 * A sync answer that was on its way meanwhile may be older than that write: it is asked for again, never judged.
 */
let ownMoves = 0;
/** Imports running: a sync dropped beside one needs no second try (the import ends with a sync). */
let importing = 0;
/** Counts the sync answers taken over that held the whole account (not a delta): `acceptServerCopy` needs a fresh one. */
let wholeAdoptions = 0;
/** While this device's manifest memory can't be read: whether a whole answer was taken over since (once per unlock). */
let unreadableWhole = false;
/** Vault manifests this device saw for the unlocked account (version and link); loaded at the first sync. */
let manifestMemory: ManifestMemory | null = null;
/** When this device first saw each trashed item in the trash (`manifest.ts` `TrashSeen`); loaded at the first sync. */
let trashSeen: TrashSeen | null = null;
/**
 * The last decrypted copy of items the server stopped sending without proof that they are gone (`materialize`): when
 * such an item comes back older than this device saw it, the newer copy is the one kept. Memory only.
 */
let ghosts = new Map<string, VaultEntry>();
const GHOSTS_MAX = 2000;
/** Decrypted copy of each row by item id (null: it couldn't be decrypted), reused while the row and its vault key stay the same. */
let decrypted = new Map<string, { row: SyncItemRow; entry: VaultEntry | null }>();
/** The vault row each open key handle came from: the handle is kept while the row's key fields stay the same. */
let openedFrom = new Map<string, SyncVaultRow>();
/** Vault names read from invitations, by vault, sealed key and encrypted name (null: it couldn't be opened). */
let invitationNames = new Map<string, string | null>();
/** Signed sharing: the last sync's verdicts (null without the checks); own writes shown without a sync reuse them. */
let verdicts: Verdicts | null = null;
/** Signed sharing: whether the last sync ran the checks (the server signs, its features are unknown, or they're sticky). */
let checksOn = false;
/**
 * Whether the last sync said every signed-in app of the account reads epoch-bound (v2) own-vault wraps (`/sync`
 * `user.account_wraps_v2`; only `true` counts, unknown is false). A hint for writing only: a server that lies can only
 * make this app write v1 wraps, as before.
 */
let accountWrapsV2 = false;
/** Item edit counters this device saw for the unlocked account (`item-revs.ts`); loaded at the first sync. */
let revMemory: RevMemory | null = null;
/** The items as the server's copy holds them (what `materialize` made), before offline changes are applied on top. */
let serverItems: VaultEntry[] = [];
/** Offline changes (desktop): the unlocked account's list, and the account it belongs to. Memory only while unlocked. */
let changes: ChangeList = emptyList();
let changesFor: string | null = null;
/** The stored list couldn't be read (not a decryption failure): nothing is written over it until it can be. */
let changesUnreadable = false;
/** The last request found no server (no answer, or 502/503/504): saves go into the list until a sync answers again. */
let offlineHint = false;
/** Held changes, by change id: the number of checked syncs when they were held (they are tried again after a newer one). */
let heldSeen = new Map<string, number>();
const subs = new Set<() => void>();

function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  subs.forEach((fn) => fn());
}

const subscribe = (fn: () => void) => {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
};
const snapshot = () => state;

export function useVault(): State {
  return useSyncExternalStore(subscribe, snapshot);
}

export const getState = () => state;
export const getAccount = () => account;
export const getBundle = () => bundle;
/** Run `fn` after every state change (outside React); returns the unsubscribe. */
export const onVaultChange = subscribe;

/** Desktop vault timeout "never": the unlocked account keys for the OS keychain; null while locked. */
export function sessionKeys(): { accountId: string; keys: Uint8Array } | null {
  if (!account || !bundle) return null;
  return { accountId: bundle.account_id, keys: account.toSessionBytes() };
}

/** Seal a profile picture (a JPEG from `makeAvatarJpeg`) with the Account Key, for `PUT /account/avatar`. */
export function sealAvatar(jpeg: Uint8Array): string {
  if (!account) throw new Error("Unlock the vault first.");
  return account.sealAvatar(jpeg);
}

/** Whether the account keys are in memory: the vault is open, or the two-step screen came up after it was unlocked. */
export const holdsKeys = (): boolean => account !== null;

onSessionLost(() => resetToLoggedOut());
onTwoStepRequired(() => enterTwoStepGate());

// Explicit locks and sign-outs apply to every open tab.
const channel = typeof BroadcastChannel === "function" ? new BroadcastChannel("passauth") : null;
channel?.addEventListener("message", (e: MessageEvent<{ type?: string }>) => {
  if (e.data?.type === "lock" && (state.status === "unlocked" || (state.status === "two-step" && account))) lock(false);
});

function store(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}
function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

// ------------------------------------------------------------- Secret Key

/** Keys of the secrets kept per account (see `secretStore`); the desktop app preloads them from its keychain. */
export const EMAIL_KEY = "pa.email";
export const secretKeyKey = (email: string) => `pa.sk.${email.trim().toLowerCase()}`;
export const rememberKey = (email: string) => `pa.remember.${email.trim().toLowerCase()}`;

export function rememberedSecretKey(email: string): string | null {
  return secretStore.get(secretKeyKey(email));
}
export function rememberSecretKey(email: string, sk: string | null) {
  secretStore.set(secretKeyKey(email), sk);
}
export function lastEmail(): string {
  return secretStore.get(EMAIL_KEY) ?? "";
}

/**
 * Tidy a Secret Key typed from paper: Secret Keys use only A–Z and 2–7 after the PA1 prefix,
 * so a 0 is always an O and an 8 always a B.
 */
export function normalizeSecretKey(input: string): string {
  const t = input.trim().toUpperCase().replace(/\s+/g, "");
  if (!t.startsWith("PA1")) return t;
  return `PA1${t.slice(3).replace(/0/g, "O").replace(/8/g, "B")}`;
}

// ---------------------------------------------------------------- startup

export async function boot() {
  if (!getTokens()) return set({ status: "logged-out", email: lastEmail() });
  if (state.status !== "loading") set({ status: "loading", serverOutdated: false });
  // Policies and features may have changed since this page last asked. A server too old for this app is not asked for
  // the vault at all (a config that can't be fetched decides nothing: the request below then says what is wrong).
  let config: PublicConfig | null;
  try {
    config = usableConfig((await refreshPublicConfig()) ?? knownPublicConfig());
  } catch {
    // The server's settings can't be fetched and this device never saw it list signed sharing: nothing of it is used.
    return set({ status: "unreachable", email: lastEmail(), serverOutdated: false });
  }
  if (serverTooOld(config)) return set({ status: "unreachable", email: lastEmail(), serverOutdated: true });
  try {
    const sync = await api("/sync");
    if (!isSyncResponse(sync)) throw new ApiError(200, "bad_response", "The server sent an unexpected response.");
    bundle = sync.bundle;
    // Delta sync: keep the (encrypted) answer, so unlocking asks only for what changed since.
    synced = null;
    if (typeof sync.cursor === "string") {
      try {
        synced = mergeSync(null, sync)?.snapshot ?? null;
      } catch {
        /* unusable: the first sync after unlocking fetches everything */
      }
    }
    set({ status: "locked", email: sync.user.email, userId: sync.user.id, name: sync.user.name, emailVerified: sync.user.email_verified });
  } catch (e) {
    // The server requires two-step login and the account has none: the session stays, for setting a method up.
    if (getTokens() && twoStepRequired(e)) return showTwoStepGate();
    // Only a server that rejects the session signs the user out; a network or server problem keeps it.
    if (!getTokens() || (e instanceof ApiError && (e.status === 401 || e.status === 403))) resetToLoggedOut();
    else set({ status: "unreachable", email: lastEmail(), serverOutdated: false });
  }
}

const FEATURES_PREFIX = "pa.server-features.";
const featuresKey = () => {
  let origin: string;
  try {
    origin = server.origin();
  } catch {
    origin = server.base;
  }
  return `${FEATURES_PREFIX}${origin}`;
};

/** The feature list this device last got from the current server's /api/config (null: never, or unreadable). */
function storedFeatures(): string[] | null {
  try {
    const v = JSON.parse(signed.deviceStore().get(featuresKey()) ?? "null") as unknown;
    return Array.isArray(v) ? v.filter((f): f is string => typeof f === "string") : null;
  } catch {
    return null;
  }
}

/**
 * The server's settings as this app may use them (review 10: breaking /api/config must not get a server past the
 * "signs shared vaults" requirement). A fetched config is used, and its feature list kept on the device. One that
 * can't be fetched (null) is "can't connect" (`UnreachableError`: no sign-in, no sync answer asked for or used)
 * unless this device has a stored list for the server that includes `signed_sharing`: then the app keeps working as
 * when offline, with the signed sharing checks on as ever.
 */
function usableConfig(config: PublicConfig | null): PublicConfig | null {
  if (config) {
    const features = Array.isArray(config.features) ? config.features.filter((f) => typeof f === "string") : [];
    const text = JSON.stringify(features);
    const store = signed.deviceStore();
    if (store.get(featuresKey()) !== text) store.set(featuresKey(), text);
    return config;
  }
  if (!storedFeatures()?.includes("signed_sharing")) throw new UnreachableError();
  return null;
}

/**
 * Before a sign-in or a new account: a server that is too old for this app (it doesn't sign shared vaults) is refused
 * with `SERVER_UPDATE_NEEDED`, before anything is sent to it. A config that can't be fetched is "can't connect" on a
 * device that never saw this server list signed sharing (`usableConfig`); otherwise it decides nothing.
 */
export async function requireCurrentServer(): Promise<void> {
  if (serverTooOld(usableConfig((await loadPublicConfig()) ?? knownPublicConfig()))) throw new Error(SERVER_UPDATE_NEEDED);
}

// ---------------------------------------------------------- two-step gate

const twoStepRequired = (e: unknown) => hasErrorCode(e, "two_step_required");

/**
 * The server answered 403 `two_step_required` (policy: every account needs two-step login, and this one has no
 * method): show the screen that only sets a method up or signs out. The keys stay in memory if they are (see
 * `continueAfterTwoStep`); live sync stops, because the server refuses it too.
 */
function enterTwoStepGate() {
  if (!getTokens()) return;
  socket?.close();
  socket = null;
  liveOrigin = null;
  if (state.status !== "two-step") set({ status: "two-step" });
}

/** Start-up found the gate: the account's address and name come from `GET /account`, which the server still answers. */
async function showTwoStepGate() {
  enterTwoStepGate();
  try {
    const a = await api<{ email?: unknown; name?: unknown; user_id?: unknown; email_verified?: unknown }>("/account");
    if (state.status !== "two-step" || !a) return;
    set({
      email: typeof a.email === "string" ? a.email : lastEmail(),
      name: typeof a.name === "string" ? a.name : "",
      userId: typeof a.user_id === "string" ? a.user_id : "",
      emailVerified: a.email_verified !== false,
    });
  } catch {
    if (state.status === "two-step" && !state.email) set({ email: lastEmail() });
  }
}

/**
 * A two-step method is set up: leave the gate. With the keys in memory the vault syncs and opens (live sync again);
 * without them the session loads again and the vault asks to be unlocked. Throws when the server still refuses (or
 * can't be reached); the gate then stays.
 */
export async function continueAfterTwoStep(): Promise<void> {
  if (state.status !== "two-step") return;
  if (afterTwoStepSetup(account !== null) === "boot") return boot();
  await sync();
  // Locked meanwhile, or a sync that was dropped: nothing to connect.
  if (getState().status !== "unlocked") return;
  connectSocket();
  void refreshPolicyViolations().catch(() => {});
  vaultKeysChanged();
}

// ------------------------------------------------------------- policies

const sameList = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Note `policy_violations` from a `GET /account` answer (Settings reads it anyway). */
export function notePolicyViolations(value: unknown) {
  const next = readViolations(value);
  if (!sameList(next, state.policyViolations)) set({ policyViolations: next });
}

/** After sign-in and unlock: ask what the account still has to change for the server's policies (servers with `policies`). */
export async function refreshPolicyViolations(): Promise<void> {
  const gen = generation;
  if (!hasFeature(await loadPublicConfig(), "policies")) return notePolicyViolations([]);
  const a = await api<{ policy_violations?: unknown } | null>("/account");
  if (gen === generation) notePolicyViolations(a?.policy_violations);
}

/**
 * The server announces a sign-out to every connection of the account, including the one that just changed
 * the master password or Secret Key and keeps its session. Ask the server: a session that is gone answers
 * 401, which signs this client out; anything but a clear "still signed in" within 10 s does the same.
 */
function confirmSignedOut() {
  let settled = false;
  const timer = setTimeout(() => {
    if (!settled) resetToLoggedOut();
    settled = true;
  }, 10_000);
  api("/account/sessions")
    .then(() => {
      settled = true;
    })
    .catch(() => {
      if (!settled) resetToLoggedOut();
      settled = true;
    })
    .finally(() => clearTimeout(timer));
}

function resetToLoggedOut() {
  dropKeys();
  synced = null;
  setTokens(null);
  set({ ...initial, status: "logged-out", email: lastEmail() });
}

/** Free the keys and every decrypted item. The encrypted rows stay (see `synced`). */
function dropKeys() {
  generation++;
  socket?.close();
  socket = null;
  liveOrigin = null;
  const old = state.vaults;
  account?.free();
  account = null;
  undecryptable = new Map();
  unopenableRows = new Map();
  newerRows = new Set();
  decrypted = new Map();
  openedFrom = new Map();
  invitationNames = new Map();
  verdicts = null;
  checksOn = false;
  accountWrapsV2 = false;
  revMemory = null;
  manifestStatus = new Map();
  unchecked = new Set();
  acceptableVaults = new Set();
  noRecordVaults = new Set();
  unreadableWhole = false;
  manifestMemory = null;
  trashSeen = null;
  ghosts = new Map();
  fullNext = false;
  avatars.clear();
  signed.endSigning();
  serverItems = [];
  changes = emptyList();
  changesFor = null;
  changesUnreadable = false;
  offlineHint = false;
  heldSeen = new Map();
  if (state.offlineChanges.length || state.offlineNotice) set({ offlineChanges: [], offlineNotice: null });
  if (old.length || state.items.length || state.invitations.length || state.blockedVaults.length || state.consents.length || state.unopenable.length || state.deviceRecordUnreadable)
    set({ vaults: [], items: [], invitations: [], blockedVaults: [], consents: [], keyChanges: [], signingNotice: null, unopenable: [], deviceRecordUnreadable: false });
  old.forEach((v) => v.key.free());
}

// ------------------------------------------------------------ registration

export interface RegisterResult {
  secretKey: string | null;
  emailVerificationRequired: boolean;
}

/**
 * The server's key-derivation minimums for new account keys (policy `min_kdf_memory_mib` / `min_kdf_iterations`), read
 * again before keys are made, so a policy the admin just raised is followed. The core then uses memory = max(128 MiB,
 * minimum) and passes = max(3, minimum). Nothing (the core's own settings) for servers without policies.
 */
async function kdfMinimums(): Promise<{ memory?: number; iterations?: number }> {
  const config = (await refreshPublicConfig()) ?? knownPublicConfig();
  if (!hasFeature(config, "policies")) return {};
  const p = readPolicies(config);
  return { memory: p.minKdfMemoryMib, iterations: p.minKdfIterations };
}

export async function register(email: string, name: string, password: string, withSecretKey: boolean): Promise<RegisterResult> {
  await requireCurrentServer();
  const kdf = await kdfMinimums();
  const init = expectStrings(await api("/auth/register/init", { body: { email }, auth: false }), "account_id", "registration_id");
  const created = core.createAccountWithKdf(init.account_id, password, withSecretKey, kdf.memory, kdf.iterations);
  const master = created.takeMaster();
  const acct = created.takeAccount();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = expectStrings(await api("/auth/register/start", { body: { registration_id: init.registration_id, message: start.message }, auth: false }), "message");
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    const vaultId = core.newId();
    const nv = acct.newVaultKey(vaultId);
    const vk = nv.takeKey();
    const meta = vk.encryptMeta(vaultId, { name: "Personal" });
    vk.free();
    const done = await api<{ email_verification_required: boolean }>("/auth/register/finish", {
      auth: false,
      body: { registration_id: init.registration_id, upload, bundle: created.bundle, name, vault: { id: vaultId, meta, wrapped_key: nv.wrapped } },
    });
    if (created.secretKey) rememberSecretKey(email, created.secretKey);
    return { secretKey: created.secretKey ?? null, emailVerificationRequired: done.email_verification_required };
  } finally {
    master.free();
    acct.free();
    created.free();
  }
}

// ------------------------------------------------------------------- login

export type LoginOutcome = { done: true } | { done: false; twoFactorToken: string; providers: string[] };

/**
 * A sign-in waiting for its two-step login (memory only): the master keys of a password sign-in, or the request key of
 * a sign-in another device approved (`device-login.ts`), whose sealed account key comes with the session; `email` is
 * the address typed on this device.
 */
type PendingSignIn = { kind: "password"; master: core.MasterKeys } | { kind: "device"; key: core.LoginRequestKey; requestId: string; email: string };
let pending: PendingSignIn | null = null;

/** Keep `next` for the two-step answer, freeing whatever was kept before. */
function holdPending(next: PendingSignIn | null) {
  const old = pending;
  pending = next;
  if (old && old !== next) (old.kind === "password" ? old.master : old.key).free();
}

/** The sign-in waiting for its two-step login, taken over by the caller (who frees it). */
function takePending(): PendingSignIn {
  const p = pending;
  pending = null;
  if (!p) throw new Error("Sign-in expired, start again.");
  return p;
}

/**
 * An approved sign-in request needs two-step login first: keep its key until the two-step answer brings the session.
 * `email` is the address typed on this device.
 */
export function holdDeviceSignIn(key: core.LoginRequestKey, requestId: string, email: string) {
  holdPending({ kind: "device", key, requestId, email });
}

/**
 * Drop a sign-in waiting for its two-step login or for the approving app's code (the user started over or left the
 * sign-in page); a session issued for one that waited for its code is signed out again.
 */
export function cancelPendingSignIn() {
  holdPending(null);
  dropApproval(true);
}

/** Thrown when the master password or Secret Key is wrong. */
export const WRONG_CREDENTIALS = "Wrong email, master password or Secret Key.";

/**
 * A sign-in's answer with every field checked: for `sign-in` a session or a two-step step, for `session` a session
 * only (the two-step answers), for `reauth` a reauth token. Anything else is the unexpected-answer error.
 */
function loginAnswer(body: unknown, want: "sign-in" | "session" | "reauth"): LoginFinishResponse {
  const a = readLoginFinish(body);
  const session = !!a && !a.two_factor_required && !!a.access_token;
  const ok = !!a && (want === "reauth" ? !!a.reauth_token : want === "session" ? session : session || a.two_factor_required === true);
  if (!a || !ok) throw new Error(UNEXPECTED_RESPONSE);
  return a;
}

async function opaqueLogin(email: string, password: string, secretKey: string | null, purpose?: "reauth") {
  if (purpose !== "reauth") await requireCurrentServer();
  const pre = readPrelogin(await api("/auth/prelogin", { body: { email }, auth: false }));
  if (!pre) throw new Error(UNEXPECTED_RESPONSE);
  if (pre.secret_key_required && !secretKey) throw new Error("secret_key_required");
  const sk = pre.secret_key_required && secretKey ? normalizeSecretKey(secretKey) : undefined;
  const master = core.deriveMasterKeys(password, sk, pre.account_id, pre.kdf, pre.secret_key_required);
  const start = core.opaqueLoginStart(master);
  let resp: { login_id: string; message: string };
  try {
    resp = expectStrings(await api("/auth/login/start", { body: { email, message: start.message }, auth: false }), "login_id", "message");
  } catch (e) {
    master.free();
    throw e;
  }
  let fin: string;
  try {
    fin = core.opaqueLoginFinish(start.state, master, resp.message);
  } catch {
    master.free();
    throw new Error(WRONG_CREDENTIALS);
  }
  const remember = rememberToken(email);
  try {
    const result = loginAnswer(
      await api("/auth/login/finish", {
        auth: purpose === "reauth",
        body: { login_id: resp.login_id, message: fin, device: deviceInfo(), purpose, remember_token: remember },
      }),
      purpose === "reauth" ? "reauth" : "sign-in",
    );
    return { master, result, secretKey: sk ?? null };
  } catch (e) {
    master.free();
    throw e;
  }
}

export async function login(email: string, password: string, secretKey: string | null): Promise<LoginOutcome> {
  const { master, result, secretKey: sk } = await opaqueLogin(email, password, secretKey);
  if (sk) rememberSecretKey(email, sk);
  if (result.two_factor_required) {
    holdPending({ kind: "password", master });
    return { done: false, twoFactorToken: result.two_factor_token ?? "", providers: result.providers ?? [] };
  }
  holdPending(null);
  await finishLogin(master, result);
  return { done: true };
}

/**
 * After a two-step login: "done" (signed in), or "confirm" for a sign-in another device approved, which then waits for
 * the approving app's code (`confirmDeviceLogin`).
 */
export type TwoStepOutcome = "done" | "confirm";

export async function verifyTwoFactor(token: string, provider: string, code: string, remember: boolean): Promise<TwoStepOutcome> {
  const result = await api("/auth/2fa/verify", { body: { two_factor_token: token, provider, code, remember }, auth: false });
  return finishPending(result);
}

/** The two-step answer's session: finish the sign-in that was waiting for it, by password or by another device's approval. */
async function finishPending(body: unknown): Promise<TwoStepOutcome> {
  const result = loginAnswer(body, "session");
  const p = takePending();
  if (p.kind === "password") {
    await finishLogin(p.master, result);
    return "done";
  }
  openDeviceApproval(p.key, p.requestId, result, p.email);
  return "confirm";
}

export async function sendTwoFactorEmail(token: string) {
  await api("/auth/2fa/email", { body: { two_factor_token: token }, auth: false });
}

/** Two-step login with a security key or passkey: server challenge → browser WebAuthn → session. */
export async function verifyTwoFactorPasskey(token: string, remember: boolean): Promise<TwoStepOutcome> {
  const { options } = await startTwoFactorPasskey(token);
  const credential = await getCredential(options);
  return finishTwoFactorPasskey(token, credential, remember);
}

/** The security-key challenge for a waiting sign-in; `key_page` (servers with `two_step_key_page`) = the server's key page. */
export async function startTwoFactorPasskey(token: string): Promise<{ options: unknown; key_page?: unknown }> {
  return api<{ options: unknown; key_page?: unknown }>("/auth/2fa/passkey/start", { body: { two_factor_token: token }, auth: false });
}

/** Send the signed assertion (from this browser, or handed back by the key page) and finish the sign-in. */
export async function finishTwoFactorPasskey(token: string, credential: unknown, remember: boolean): Promise<TwoStepOutcome> {
  const result = await api("/auth/2fa/passkey/finish", { body: { two_factor_token: token, credential, remember }, auth: false });
  return finishPending(result);
}

function rememberToken(email: string) {
  return secretStore.get(rememberKey(email)) ?? undefined;
}

async function finishLogin(master: core.MasterKeys, result: LoginFinishResponse) {
  dropKeys();
  // A new session (maybe another account) starts from the whole account.
  synced = null;
  try {
    setTokens({ access: result.access_token, refresh: result.refresh_token });
    if (result.remember_token) secretStore.set(rememberKey(result.email), result.remember_token);
    secretStore.set(EMAIL_KEY, result.email);
    bundle = result.bundle;
    account = master.unlock(bundle);
  } finally {
    master.free();
  }
  set({ email: result.email, userId: result.user_id });
  void refreshPublicConfig();
  if (!(await openVault())) return;
  connectSocket();
}

/** Shown when an approved sign-in's sealed key doesn't open with this device's request key, or doesn't fit the account. */
export const DEVICE_KEY_UNUSABLE =
  "This sign-in couldn't be finished: the approval doesn't match the request this device made. Start again, and check that both devices show the same words.";

/**
 * A sign-in another device approved, opened and waiting for the code the approving app shows (memory only): until the
 * code is confirmed, nothing of it is used or kept, not even the session's tokens.
 */
let approved: { login: core.ApprovedLogin; result: LoginFinishResponse; email: string } | null = null;

/** Drop the approval waiting for its code; `signOut`: also end the session the server issued for it (best effort). */
function dropApproval(signOut: boolean) {
  const a = approved;
  approved = null;
  if (!a) return;
  if (signOut) endSession(a.result.access_token);
  a.login.free();
}

/**
 * Open the sealed account key of a sign-in another device approved (`device-login.ts`) with the request's key, and keep
 * it until the user types the approving app's code (`confirmDeviceLogin`): only the real account key gives that code,
 * so a server can't hand this device a key of its own choosing. `email` is the address typed on this device. Takes over
 * `key` and frees it. When the sealed key can't be opened, the session the server just issued is signed out again and
 * nothing is kept.
 */
export function openDeviceApproval(key: core.LoginRequestKey, requestId: string, result: LoginFinishResponse, email: string): void {
  dropApproval(true);
  let login: core.ApprovedLogin;
  try {
    const sealed = (result as { sealed_key?: unknown }).sealed_key;
    if (typeof sealed !== "string" || !sealed) throw new Error("no sealed key");
    login = key.open(sealed, result.user_id, requestId);
  } catch {
    endSession(result.access_token);
    throw new Error(DEVICE_KEY_UNUSABLE);
  } finally {
    key.free();
  }
  approved = { login, result, email };
}

/** Whether a sign-in another device approved waits for the approving app's code. */
export const awaitsDeviceCode = (): boolean => approved !== null;

/** How entering the code went: signed in, a wrong code (with the tries left), or stopped after the third wrong one. */
export type DeviceCodeResult = { kind: "done"; email: string } | Exclude<CodeOutcome, { kind: "confirmed" }>;

/**
 * Check the code the approving app shows. Right: the account opens without the master password and the sign-in goes on
 * exactly as after a password sign-in (tokens, remember token and email are kept, and a Secret Key that came along is
 * kept for the typed email unless a different one is kept for it already). The third wrong code ends it: the session
 * is signed out and everything dropped. Throws for anything but 6 digits (not counted).
 */
export async function confirmDeviceLogin(code: string): Promise<DeviceCodeResult> {
  const a = approved;
  if (!a) throw new Error("Sign-in expired, start again.");
  const outcome = checkCode(a.login, code);
  if (outcome.kind === "wrong") return outcome;
  if (outcome.kind === "stopped") {
    dropApproval(true);
    return outcome;
  }
  approved = null;
  const result = a.result;
  let opened: core.Account;
  let received: string | null;
  try {
    opened = a.login.unlock(result.bundle);
    received = a.login.secretKey() ?? null;
  } catch {
    endSession(result.access_token);
    throw new Error(DEVICE_KEY_UNUSABLE);
  } finally {
    a.login.free();
  }
  dropKeys();
  // A new session (maybe another account) starts from the whole account.
  synced = null;
  setTokens({ access: result.access_token, refresh: result.refresh_token });
  if (result.remember_token) secretStore.set(rememberKey(result.email), result.remember_token);
  secretStore.set(EMAIL_KEY, result.email);
  const keep = secretKeyToKeep(a.email, result.email, received, rememberedSecretKey(result.email));
  if (keep) rememberSecretKey(result.email, keep);
  bundle = result.bundle;
  account = opened;
  set({ email: result.email, userId: result.user_id });
  void refreshPublicConfig();
  if (await openVault()) connectSocket();
  return { kind: "done", email: result.email };
}

/** Sign out a session this app won't keep (best effort): one issued for a sign-in that can't be finished or was cancelled. */
export function endSession(accessToken: string) {
  void api("/auth/logout", { method: "POST", auth: false, headers: { authorization: `Bearer ${accessToken}` } }).catch(() => {});
}

/**
 * The first sync after the keys are in memory (sign-in, unlock, restore). False when the server requires two-step
 * login first: the gate is showing and the keys stay for `continueAfterTwoStep`. Other failures are thrown.
 */
async function openVault(): Promise<boolean> {
  await openVaultChanges();
  try {
    await sync();
  } catch (e) {
    if (twoStepRequired(e) && getTokens() && account) {
      enterTwoStepGate();
      return false;
    }
    throw e;
  }
  void refreshPolicyViolations().catch(() => {});
  vaultKeysChanged();
  return true;
}

/** Before the first sync after the keys are in memory: this account's offline changes (desktop). */
async function openVaultChanges() {
  if (!offlineOn() || !account || !bundle) return;
  const accountId = bundle.account_id;
  const gen = generation;
  let list = emptyList();
  let notice: string | null = null;
  try {
    const sealed = await offlineStore()!.get(accountId);
    if (gen !== generation || !account) return;
    if (sealed) list = parseList(account.openOfflineChanges(sealed));
  } catch (e) {
    if (gen !== generation || !account) return;
    if (!(e instanceof Error && e.message === "decrypt_failed")) {
      // Can't be read now (storage error, a newer list format, damaged): kept as it is, and nothing is written over it.
      changes = emptyList();
      changesFor = null;
      changesUnreadable = true;
      set({ offlineNotice: LIST_UNREADABLE });
      return;
    }
    // Doesn't open for this account: dropped (replaced at the next change), and the user is told.
    list = emptyList();
    notice = LIST_DROPPED;
  }
  if (gen !== generation || !account) return;
  changes = list;
  changesFor = accountId;
  changesUnreadable = false;
  if (notice || state.offlineNotice) set({ offlineNotice: notice });
}

/** Hide the notice that an unopenable list was removed (the one about an unreadable list stays). */
export function dismissOfflineNotice() {
  if (state.offlineNotice === LIST_DROPPED) set({ offlineNotice: null });
}

let afterVaultKeys: (() => Promise<void>) | null = null;

/**
 * `fn` runs (in the background, its failures ignored) after the vault opened, a vault was created and vault keys were
 * replaced: when personal vaults may need new emergency-access wraps. One hook; null removes it.
 */
export function onVaultKeysChange(fn: (() => Promise<void>) | null) {
  afterVaultKeys = fn;
}

function vaultKeysChanged() {
  const fn = afterVaultKeys;
  if (fn && account && state.status === "unlocked") void fn().catch(() => {});
}

/** Shown with the vault notices (emergency access); null hides it. Cleared when the vault locks. */
export function setEmergencyNotice(text: string | null) {
  if (state.emergencyNotice !== text) set({ emergencyNotice: text });
}

/** Unlock a locked session locally (the bundle is already cached). */
export async function unlock(password: string, secretKey: string | null) {
  if (!bundle) throw new Error("Sign in again to unlock this vault.");
  const sk = secretKey ? normalizeSecretKey(secretKey) : undefined;
  const master = core.deriveMasterKeys(password, sk, bundle.account_id, bundle.kdf, bundle.secret_key_enabled);
  dropKeys();
  try {
    account = master.unlock(bundle);
  } catch {
    throw new Error("Wrong master password or Secret Key.");
  } finally {
    master.free();
  }
  void refreshPublicConfig();
  let opened: boolean;
  try {
    opened = await openVault();
  } catch (e) {
    dropKeys();
    throw e;
  }
  if (sk) rememberSecretKey(state.email, sk);
  if (opened) connectSocket();
}

/** Open a locked session with keys saved by `sessionKeys()` (desktop, vault timeout "never") instead of the master password. */
export async function restoreUnlocked(accountId: string, keys: Uint8Array) {
  if (!bundle) throw new Error("Sign in again to unlock this vault.");
  if (bundle.account_id !== accountId) throw new Error("The saved keys belong to another account.");
  dropKeys();
  const restored = core.accountFromSessionBytes(accountId, keys);
  // The id is only one the core authenticated (round 5): the bundle's private key must open under these keys with its
  // account id bound. Otherwise the saved keys aren't used (the master password is asked for).
  if (!restored.matchesBundle(bundle)) {
    restored.free();
    throw new Error("The saved keys don't match this account. Unlock with your master password.");
  }
  account = restored;
  let opened: boolean;
  try {
    opened = await openVault();
  } catch (e) {
    dropKeys();
    throw e;
  }
  if (opened) connectSocket();
}

/** Fresh proof of the master password for sensitive settings. */
export async function reauth(password: string): Promise<string> {
  // Before the first sync of a session (the two-step screen at start-up) the bundle isn't known: the server's
  // prelogin says whether the Secret Key is needed, and the one this app remembers is used then.
  const sk = bundle && !bundle.secret_key_enabled ? null : rememberedSecretKey(state.email);
  const { master, result } = await opaqueLogin(state.email, password, sk, "reauth");
  master.free();
  if (typeof result.reauth_token !== "string" || !result.reauth_token) throw new Error("reauth_required");
  return result.reauth_token;
}

/** Lock this tab; `everywhere` also locks the vault in this browser's other tabs. */
export function lock(everywhere = true) {
  dropKeys();
  set({ status: "locked", vaults: [], items: [], revision: 0, warnings: [], invitations: [], emergencyNotice: null, blockedVaults: [], consents: [], keyChanges: [], signingNotice: null });
  if (everywhere) channel?.postMessage({ type: "lock" });
}

export async function logout() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    /* already gone */
  }
  resetToLoggedOut();
}

/**
 * Forget a device (servers with `forget_device`): every session it holds ends at once and the server drops its record
 * with its "remember this device" token, so its next sign-in counts as a new device and asks for two-step login again.
 * When it is this device (`current` in the answer), this app is signed out too.
 */
export async function forgetDevice(deviceId: string): Promise<{ signedOut: number; current: boolean }> {
  const r = await api<{ signed_out?: unknown; current?: unknown } | null>(`/account/devices/${encodeURIComponent(deviceId)}/forget`, {
    method: "POST",
    body: {},
  });
  const current = r?.current === true;
  if (current) {
    // The server forgot the token; a copy kept here would only be refused.
    if (state.email) secretStore.set(rememberKey(state.email), null);
    resetToLoggedOut();
  }
  return { signedOut: typeof r?.signed_out === "number" ? r.signed_out : 0, current };
}

export function dismissWarnings() {
  set({ warnings: [] });
}

// -------------------------------------------------------------------- sync

let running: Promise<void> | null = null;
let queued: Promise<void> | null = null;

/**
 * Fetch and decrypt the vault. Calls are serialised (a call made while one runs gets a fresh run
 * afterwards, so a write is always reflected), and a result that arrives after a lock is dropped.
 */
export function sync(): Promise<void> {
  if (queued) return queued;
  if (!running) {
    running = doSync().finally(() => (running = null));
    return running;
  }
  queued = running
    .catch(() => {})
    .then(() => {
      queued = null;
      running = doSync().finally(() => (running = null));
      return running;
    });
  return queued;
}

const UNEXPECTED_SYNC = "The server sent an unexpected response. Reload the page to try again.";

/**
 * How signed sharing's checks run for this sync answer (they always run: a server that doesn't sign is refused before
 * its answer is asked for, `serverTooOld`). "proven": the server lists `signed_sharing`, or the checks are sticky (this
 * device remembers signed state for the account, or the answer carries any identity, share, roster or key pins).
 * "unproven": its features are unknown (`/api/config` couldn't be fetched): the checks run, but nothing that keeps them
 * on for good is written until the server shows it signs (review M-A).
 */
function decideChecks(acct: core.Account, snap: Snapshot): "proven" | "unproven" {
  return hasFeature(knownPublicConfig(), "signed_sharing") || signed.checksRemembered(acct, snap) ? "proven" : "unproven";
}

/** The sync error for a server this app refuses; what the vault shows stays (as when the server can't be reached), with a notice. */
function serverRefused(): Error {
  if (!state.serverOutdated) set({ serverOutdated: true });
  return new Error(SERVER_UPDATE_NEEDED);
}

/**
 * Before a write: nothing is written to a server this app refuses (its config, as last fetched, doesn't list signed
 * sharing). The vault as shown stays readable, as when the server can't be reached.
 */
function requireWritableServer() {
  if (serverTooOld(knownPublicConfig())) throw serverRefused();
}

/** Whether the last sync ran the signed sharing checks: then every vault is checked and every change signed. */
function signedSharingOn(): boolean {
  return checksOn;
}

/** The account's `/sync` `user` again (its signing identity, after another device made it first), without merging anything. */
async function refetchUser(): Promise<unknown> {
  const data = await api(synced?.cursor ? `/sync?since=${encodeURIComponent(synced.cursor)}` : "/sync");
  return isSyncResponse(data) ? data.user : null;
}

/** Full fetches after an answer that is older than an own write already shown, before it counts as the server's answer. */
const BEHIND_RUNS = 2;
/** Answers asked for in one sync at most; after that the sync ends without taking anything over. */
const SYNC_ROUNDS = 8;

/**
 * One sync: fetch, check, and only then take the answer over. Nothing of an answer replaces the copy (or what is
 * shown) before signed sharing and the vault manifests have judged it:
 *
 * - An own write was shown while the answer was on its way or being checked (`ownMoves`: an import's batches, a first
 *   manifest, old trash): the answer may be older than that write and what this device remembers of it, so it is
 *   neither judged nor taken over; it is asked for again, without counting toward any limit below. A sync that never
 *   gets an answer of its own this way (`SYNC_ROUNDS`) ends without one: nothing changes, no warning; an import ends
 *   with a sync of its own, anything else is asked for once more.
 * - An answer older than an own write this app already showed ("behind": a vault's number below it) is not taken
 *   over: the whole account is fetched again, up to `BEHIND_RUNS` times. If the server keeps answering so, the answer
 *   counts as its answer and is checked like any other, so a rollback of the own write is reported (review 1).
 * - A vault whose manifest is two or more steps ahead of the remembered one needs the vault's manifest log
 *   (`checkManifests`). While the log can't be fetched the answer is not taken over at all: the copy, what is shown
 *   and every verdict stay as they were, writes into that vault wait, no warning is raised, and the next sync asks again.
 * - A verdict that would raise a warning ("rollback", "mismatch", "incomplete") from an answer merged into the copy
 *   (a delta) gets one fetch of the whole account first; only that answer's verdict is shown. A whole answer whose
 *   "rollback" is against a manifest another tab remembered while this ran (its write may be newer than the answer)
 *   gets one more fetch too.
 * - An answer whose `revision` is below the one shown is dropped only when it can be a race (the copy moved since the
 *   request was sent, `fetchSync`). Otherwise the server went back (a database restored from a backup): the whole
 *   account is fetched once and judged like any answer, so the vaults' checks report it and can be accepted.
 */
async function doSync() {
  if (!account) return;
  const gen = generation;
  // The last answer known, so a refresh on its way (sign-in, unlock) doesn't hold the sync up. A config that can't be
  // fetched on a device that never saw this server list signed sharing: nothing is asked for (`usableConfig`).
  const config = usableConfig(knownPublicConfig() ?? (await loadPublicConfig()));
  if (gen !== generation || !account) return;
  // A server too old for this app (it doesn't sign shared vaults): its vault is neither asked for nor used.
  if (serverTooOld(config)) throw serverRefused();
  const delta = hasFeature(config, "delta_sync");
  deltaOn = delta;
  let cursor = delta && !fullNext ? (synced?.cursor ?? null) : null;
  fullNext = false;
  let behindRuns = 0;
  let refetched = false;
  let raced = false;
  for (let round = 1; ; round++) {
    // What another tab remembered before this answer is asked for: what changes after it changed during the run.
    const memory = manifestMemoryFor(account);
    memory.refresh();
    // A record that can't be read: one whole answer, so the reset (if it comes to that) starts from a full sync.
    if (memory.unreadable && !unreadableWhole) cursor = null;
    const moves = ownMoves;
    // An own write shown since this round began: the answer may predate it. Ask again (or give up without an answer).
    const again = (): boolean => {
      if (round >= SYNC_ROUNDS) {
        if (!importing) setTimeout(() => void sync().catch(() => {}), 0);
        return false;
      }
      if (cursor !== null) cursor = synced?.cursor ?? null;
      return true;
    };
    let merged = await fetchSync(cursor, gen);
    // A delta this client can't use (malformed, or about data it no longer has): fetch everything once.
    if (merged === "full") {
      cursor = null;
      merged = await fetchSync(null, gen);
    }
    if (!merged || merged === "full" || gen !== generation || !account) return;
    const whole = cursor === null;
    if (ownMoves !== moves) {
      if (again()) continue;
      return;
    }
    // The copy this answer was merged into (or replaces): if it moves before the answer is taken over, ask again.
    const held = synced;
    const snap = merged.snapshot;
    // "Me" is the account the core unlocked: an answer for another account is never used.
    if (snap.user.id !== signed.accountIdOf(account)) throw new Error(ACCOUNT_MISMATCH);
    // Also for an answer that replaces the copy (a full fetch merges into nothing, so `mergeSync` can't tell).
    const behind =
      merged.behind ||
      (!!held &&
        Object.entries(held.own).some(([id, own]) => {
          const now = snap.vaults.find((x) => x.id === id)?.seq;
          return typeof now === "number" && now < own;
        }));
    if (behind && behindRuns < BEHIND_RUNS) {
      behindRuns++;
      cursor = null;
      continue;
    }
    // Signed sharing: check every vault and invitation before anything of them is used.
    const mode = decideChecks(account, snap);
    const signs = await signed.prepareSigning(account, snap.user, refetchUser, mode === "proven");
    if (gen !== generation || !account) return;
    // The server answered that it doesn't sign (404 on the identity) before it ever showed it does: too old, never used.
    if (!signs) throw serverRefused();
    const checked = await signed.verifySnapshot(snap.vaults, snap.invitations);
    // Never shown unchecked: without verdicts nothing of this answer is used.
    if (gen !== generation || !account || !checked) return;
    let result: { checks: Map<string, VaultCheck>; changed: Set<string> } | null;
    try {
      result = await checkManifests(snap, checked, gen);
    } catch (e) {
      if (!(e instanceof LogUnavailable)) throw e;
      // The sync failed for that vault, and this app takes an answer over as a whole or not at all.
      if (gen === generation) unchecked.add(e.vaultId);
      throw e.cause;
    }
    if (!result || gen !== generation || !account) return;
    const { checks, changed } = result;
    if (ownMoves !== moves || synced !== held) {
      if (again()) continue;
      return;
    }
    // A verdict that would raise a warning the vault doesn't show yet, from a delta: the whole account once, first.
    // (A vault that already has its warning, from a whole answer, keeps it without fetching everything every time.)
    const fresh = (id: string, c: VaultCheck) => unresolved(c.status) && !unresolved(manifestStatus.get(id));
    const failing = !whole && !refetched && [...checks].some(([id, c]) => fresh(id, c));
    // From a whole answer: a "rollback" against what another tab remembered while this ran. That tab's write may be
    // newer than this answer (two tabs, review 8): the whole account once more before the warning counts.
    const outrun = whole && !raced && [...checks].some(([id, c]) => c.status === "rollback" && changed.has(id) && fresh(id, c));
    if (failing || outrun) {
      if (failing) refetched = true;
      else raced = true;
      cursor = null;
      continue;
    }
    adopt(snap, checked, checks, whole);
    void manifestUpkeep(snap, gen);
    return;
  }
}

/** A vault's verdict for one sync answer, with what to remember when it is "ok". */
interface VaultCheck {
  status: ManifestStatus;
  version: number;
  link: string | null;
  /** Unresolved, and the served copy is consistent in itself (`acceptVault`): accepting it needs no write. */
  acceptable?: boolean;
  /** With `acceptable`: the server shows no record at all, so accepting forgets what this device remembers. */
  noRecord?: boolean;
}

/** A vault's manifest log couldn't be fetched (no answer, a 5xx, a 429): the answer that needs it isn't checked yet. */
class LogUnavailable extends Error {
  readonly vaultId: string;
  readonly cause: unknown;
  constructor(vaultId: string, cause: unknown) {
    super("manifest log unavailable");
    this.vaultId = vaultId;
    this.cause = cause;
  }
}

/** Requests for one vault's manifest log at most (25 × 2000 entries); a log that needs more pages doesn't connect. */
const LOG_REQUESTS = 25;

/**
 * A vault's manifest log after `after` (`GET /vaults/{id}/manifest-log`), all pages: null when the server's answer is
 * no log this app can use (404, 400, a malformed answer, more pages than `LOG_REQUESTS`), which is a "mismatch".
 * Throws `LogUnavailable` when no answer could be had (network, 5xx, 429): the vault then isn't checked yet.
 */
async function manifestLog(vaultId: string, after: number): Promise<unknown[] | null> {
  const entries: unknown[] = [];
  let from = after;
  for (let requests = 1; requests <= LOG_REQUESTS; requests++) {
    let answer: { entries?: unknown; more?: unknown } | null;
    try {
      answer = await api<{ entries?: unknown; more?: unknown } | null>(`/vaults/${vaultId}/manifest-log?after=${from}`);
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 400)) return null;
      throw new LogUnavailable(vaultId, e);
    }
    if (!answer || !Array.isArray(answer.entries)) return null;
    let last = from;
    for (const raw of answer.entries as unknown[]) {
      // Entries go to the core as the server sent them (it skips what is no entry, the same way in every app). Only
      // the next page's start is read here.
      entries.push(raw);
      const seq = (raw as { seq?: unknown } | null)?.seq;
      if (typeof seq === "number" && Number.isSafeInteger(seq) && seq >= 1) last = Math.max(last, seq);
    }
    if (answer.more !== true) return entries;
    // "More" without getting anywhere never ends: no log.
    if (last <= from) return null;
    from = last;
  }
  return null;
}

/**
 * Check every vault of a sync answer against its manifest before the answer is taken over (`doSync`): each vault that
 * passed the signed sharing checks (`checked`) and whose key opens, with all its item rows of `snap`, against the
 * manifest this device remembers (`verifyVault`). "need_log" fetches the vault's manifest log and checks again with
 * it. The verdict is the manifest's alone. A row that doesn't open doesn't change it (final review, T1): the manifest
 * doesn't cover `item_key`, so a server can make any item fail to open on one device, and a verdict that held the
 * vault's writes for it only pushed its user to delete a good item for everyone. Such a row is listed with a notice
 * instead (`materialize`), or kept as the copy this device already opened.
 *
 * A vault that doesn't check out is also checked with nothing remembered (`acceptVault`): whether its warning can be
 * cleared on this device alone decides what the warning offers.
 *
 * `checks` holds a verdict for every vault that was checked (absent: "none", nothing to check); it is empty when this
 * device's memory can't be read (`ManifestMemory.unreadable`: nothing is checked against it, and `adopt` leaves every
 * vault that has a manifest unchecked). `changed`: the vaults whose remembered manifest another tab changed since this
 * sync round began. Null when the vault was locked meanwhile.
 */
async function checkManifests(snap: Snapshot, checked: Verdicts, gen: number): Promise<{ checks: Map<string, VaultCheck>; changed: Set<string> } | null> {
  const acct = account;
  if (!acct) return null;
  const out = new Map<string, VaultCheck>();
  const feature = hasFeature(knownPublicConfig(), "vault_manifest");
  const memory = manifestMemoryFor(acct);
  // What another tab remembered meanwhile counts.
  const changed = memory.refresh();
  if (memory.unreadable) return { checks: out, changed };
  const rowsByVault = new Map<string, SyncItemRow[]>();
  for (const row of snap.items.values()) {
    const list = rowsByVault.get(row.vault_id);
    if (list) list.push(row);
    else rowsByVault.set(row.vault_id, [row]);
  }
  for (const v of snap.vaults) {
    if (checked.vaults.get(v.id)?.status !== "ok") continue;
    const remembered = memory.get(v.id);
    if (!checkApplies(feature, v, remembered)) continue;
    // Its own handle: the ones shown may be freed while the log is fetched.
    let key: core.VaultKey;
    try {
      const epoch = typeof v.key_epoch === "number" ? v.key_epoch : 0;
      key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind, epoch, signed.legacyWrapAllowed(v.id, epoch));
    } catch {
      continue;
    }
    try {
      const rows = rowsByVault.get(v.id) ?? [];
      let check = verifyVault(key, v, remembered, rows);
      if (check.status === "need_log") {
        const log = await manifestLog(v.id, remembered?.version ?? 0);
        if (gen !== generation || account !== acct) return null;
        check = log ? verifyVault(key, v, remembered, rows, log) : { ...check, status: "mismatch" };
      }
      const status: ManifestStatus = check.status === "need_log" ? "mismatch" : check.status;
      // What "Use the server's copy" could do here: nothing remembered, the served record against the served rows.
      const local = unresolved(status) ? acceptVault(key, v, rows) : null;
      out.set(
        v.id,
        status === "ok"
          ? { status, version: check.version, link: check.link }
          : {
              status,
              version: remembered?.version ?? 0,
              link: remembered?.link ?? null,
              ...(local && acceptable(local) ? { acceptable: true } : {}),
              ...(local?.status === "none" ? { noRecord: true } : {}),
            },
      );
    } finally {
      key.free();
    }
  }
  return { checks: out, changed };
}

/**
 * Take a checked sync answer over: it becomes the copy writes start from, each vault gets the verdict `checkManifests`
 * gave it, "ok" manifests are remembered (version and link, together with the copy that carries them; nothing else is
 * ever remembered and nothing lowered), and the state is decrypted from it.
 */
function adopt(snap: Snapshot, checked: Verdicts, checks: Map<string, VaultCheck>, whole: boolean) {
  const acct = account;
  if (!acct) return;
  if (whole) wholeAdoptions++;
  checksOn = true;
  verdicts = checked;
  if (state.serverOutdated) set({ serverOutdated: false });
  accountWrapsV2 = snap.user.account_wraps_v2 === true;
  // Kept with or without delta sync: the vault rows (their manifests) and item rows are what writes start from.
  synced = snap;
  // Kept only when it is this unlocked account's own bundle (round 5: never another account id's).
  if (acct.matchesBundle(snap.bundle)) bundle = snap.bundle;
  const memory = manifestMemoryFor(acct);
  const statuses = new Map<string, ManifestStatus>();
  const pending = new Set<string>();
  const local = new Set<string>();
  const recordless = new Set<string>();
  for (const v of snap.vaults) {
    if (memory.unreadable) {
      // Nothing was checked against the record: a vault that has a manifest is unchecked (never an earlier "ok" over
      // these rows) and takes no writes; a vault without one is written as before. A warning it had stays.
      const was = manifestStatus.get(v.id);
      if (unresolved(was)) {
        statuses.set(v.id, was as ManifestStatus);
        if (acceptableVaults.has(v.id)) local.add(v.id);
        if (noRecordVaults.has(v.id)) recordless.add(v.id);
      } else if (manifestSeq(v) > 0 || (typeof v.manifest === "string" && v.manifest.length > 0)) pending.add(v.id);
      continue;
    }
    const c = checks.get(v.id);
    if (!c) continue;
    statuses.set(v.id, c.status);
    if (c.acceptable) local.add(v.id);
    if (c.acceptable && c.noRecord) recordless.add(v.id);
    if (c.status === "ok") memory.raise(v.id, c.version, c.link);
  }
  memory.flush();
  // How often in a row the record couldn't be read, with a whole answer among them: then the reset is offered.
  const failedReads = memory.noteRead(memory.unreadable);
  if (memory.unreadable && whole) unreadableWhole = true;
  if (!memory.unreadable) unreadableWhole = false;
  const offerReset = memory.unreadable && unreadableWhole && failedReads >= UNREADABLE_READS;
  if (state.deviceRecordUnreadable !== offerReset) set({ deviceRecordUnreadable: offerReset });
  manifestStatus = statuses;
  unchecked = pending;
  acceptableVaults = local;
  noRecordVaults = recordless;
  materialize(snap);
  void signed.flushPins().catch(() => {});
  afterCheckedSync();
}

/**
 * `GET /sync`, or with a cursor only what changed since, merged into `synced`. Null when the answer is dropped
 * (locked meanwhile, or older than what is shown and possibly a race); "full" when a delta can't be used.
 *
 * An answer with a lower `revision` than the one shown is a race only when the copy moved since this request was sent
 * (an own write was applied, or another answer taken over): then it is dropped as before. With the copy unmoved the
 * server itself went back (its database was restored from a backup): the answer is not ignored. A delta is asked for
 * again as the whole account, and the whole answer goes on to be judged like any other (`doSync`: signed sharing, the
 * vaults' manifests), which reports the rollback and lets the user accept the server's copy (final review 2).
 */
async function fetchSync(cursor: string | null, gen: number): Promise<Merged | "full" | null> {
  const sentFrom = synced;
  const data = await api(cursor ? `/sync?since=${encodeURIComponent(cursor)}` : "/sync");
  if (gen !== generation || !account) return null;
  if (!isSyncResponse(data)) throw new Error(UNEXPECTED_SYNC);
  if (state.status === "unlocked" && data.revision < state.revision) {
    if (synced !== sentFrom) return null;
    if (cursor) return "full";
  }
  let merged: Merged | null = null;
  try {
    merged = mergeSync(cursor ? synced : null, data);
  } catch {
    /* malformed */
  }
  if (merged) return merged;
  if (cursor) return "full";
  throw new Error(UNEXPECTED_SYNC);
}

const byName = new Intl.Collator(undefined, { sensitivity: "base" });

/** The unlocked account's item counters on this device (`item-revs.ts`), per server and account. */
function revMemoryFor(acct: core.Account): RevMemory {
  const scope = signed.scopeOf(acct);
  if (revMemory?.scope !== scope) revMemory = new RevMemory(signed.deviceStore(), scope);
  return revMemory;
}

/**
 * Item rollback detection for a freshly decrypted item: its edit counter checked against what this device saw. A
 * rollback keeps the newer copy this page still shows (with the row's revision, so an edit saves over the server's
 * copy) or shows the served one; both are marked for the warning. Counted in `rollbacks` for the sync notice.
 */
function checkRollback(revs: RevMemory, entry: VaultEntry, shown: VaultEntry | null, rollbacks: { kept: number; shown: number }): VaultEntry {
  const served = revOf(entry.item);
  if (revs.check(entry.id, served) !== "rollback") return entry;
  if (shown && shown.vaultId === entry.vaultId && revOf(shown.item) > served) {
    rollbacks.kept++;
    return { ...shown, revision: entry.revision, deletedAt: entry.deletedAt, rollback: true };
  }
  rollbacks.shown++;
  return { ...entry, rollback: true };
}

/** Who may delete for good a row that holds an item from a newer app: the vault's owners and admins. */
const mayDeleteNewer = (role: Role): boolean => role === "owner" || role === "admin";

/** A row's decrypted item, or why there is none: "newer" (`isNewerItemError`) or "unopenable" (everything else). */
function openRow(key: core.VaultKey, row: SyncItemRow): VaultEntry | "newer" | "unopenable" {
  const enc: EncryptedItem = { id: row.id, vault_id: row.vault_id, key: row.item_key, data: row.data };
  try {
    const item = key.decryptItem(enc) as Item;
    // In the trash exactly when `deleted_at` is not null (a missing field reads as null).
    return { id: row.id, item, vaultId: row.vault_id, revision: row.revision, deletedAt: row.deleted_at ?? null, enc };
  } catch (e) {
    return isNewerItemError(e) ? "newer" : "unopenable";
  }
}

function decryptRow(key: core.VaultKey, row: SyncItemRow): VaultEntry | null {
  const opened = openRow(key, row);
  return typeof opened === "string" ? null : opened;
}

/**
 * For a served row that doesn't decrypt: the copy of the same item this device opened before, when the row is that
 * item unchanged (same id, vault and `data`) and only its `item_key` differs. An honest server never changes a key
 * without the data, and the vault's manifest covers the data, so the device goes on with the row it has (final
 * review 1, T1a): the item stays shown and editable, nothing is listed or warned. `held` is the copy shown until now,
 * `ghost` the last copy shown of an item the server had stopped sending. Returns the entry and the item key to keep.
 */
function heldCopy(row: SyncItemRow, held: { row: SyncItemRow; entry: VaultEntry | null } | undefined, ghost: VaultEntry | undefined): { entry: VaultEntry; itemKey: string } | null {
  const deletedAt = row.deleted_at ?? null;
  if (held?.entry && held.row.vault_id === row.vault_id && held.row.data === row.data && typeof row.data === "string")
    return { entry: { ...held.entry, revision: row.revision, deletedAt }, itemKey: held.row.item_key };
  if (ghost && ghost.vaultId === row.vault_id && ghost.enc.data === row.data && typeof row.data === "string")
    return { entry: { ...ghost, revision: row.revision, deletedAt }, itemKey: ghost.enc.key };
  return null;
}

/** The unlocked account's remembered vault manifests on this device (`manifest.ts`), per server and account. */
function manifestMemoryFor(acct: core.Account): ManifestMemory {
  const scope = signed.scopeOf(acct);
  if (manifestMemory?.scope !== scope) manifestMemory = new ManifestMemory(signed.deviceStore(), scope);
  return manifestMemory;
}

/** When this device first saw each trashed item of the unlocked account in the trash, per server and account. */
function trashSeenFor(acct: core.Account): TrashSeen {
  const scope = signed.scopeOf(acct);
  if (trashSeen?.scope !== scope) trashSeen = new TrashSeen(signed.deviceStore(), scope);
  return trashSeen;
}

/**
 * Remember a manifest this app stored itself (an own write shown without asking, a first manifest, a baseline): its
 * version and the link the builder gave for it, at the moment the copy takes it over.
 */
function rememberManifest(vaultId: string, sent: Pick<ManifestEntry, "seq" | "link">) {
  if (!account) return;
  const memory = manifestMemoryFor(account);
  memory.raise(vaultId, sent.seq, sent.link);
  memory.flush();
  // The copy and the memory moved without the server: an answer on its way may be older than both (`doSync`).
  ownMoves++;
}

/**
 * Decrypt `snap` into the state. A vault's key handle is kept while its key fields stay the same (otherwise it is
 * opened again and its items decrypted again), and an item whose ciphertext didn't change keeps its decrypted copy,
 * so a small delta costs little. Warnings are worked out again each time, as before.
 *
 * Vault manifests: the verdicts are `manifestStatus`, set when the sync answer was taken over (`adopt`); an own write
 * shown without asking keeps them (this app made that manifest). Nothing is checked here.
 */
function materialize(snap: Snapshot): void {
  const acct = account;
  if (!acct) return;
  const warnings: string[] = [];
  const before = state.vaults;
  const previous = new Map(before.map((v) => [v.id, v]));
  const kept = new Set<core.VaultKey>();
  const opened = new Map<string, SyncVaultRow>();
  const vaults: Vault[] = [];
  const blocked: BlockedVault[] = [];
  const consents: ConsentVault[] = [];
  for (const v of snap.vaults) {
    const verdict = verdicts?.vaults.get(v.id);
    if (verdicts && verdict?.status === "consent") {
      // Never accepted: only its name is read (the key opened for that alone and freed), nothing else is used.
      consents.push({ id: v.id, role: v.role, name: consentName(acct, v), consent: verdict.consent });
      continue;
    }
    if (verdicts && verdict?.status !== "ok") {
      // Not verified: never opened, so none of its items is decrypted, filled, saved to or shown.
      blocked.push({
        id: v.id,
        role: v.role,
        reason: verdict?.status === "refused" ? verdict.reason : signed.CHECK_LATER,
        ...(verdict?.status === "refused" && verdict.changed ? { changed: verdict.changed } : {}),
      });
      continue;
    }
    const old = previous.get(v.id);
    const from = openedFrom.get(v.id);
    let key: core.VaultKey;
    if (old && from && !vaultKeyChanged(from, v)) {
      key = old.key;
      kept.add(key);
    } else {
      try {
        const epoch = typeof v.key_epoch === "number" ? v.key_epoch : 0;
        key = acct.openVaultKey(v.id, v.wrapped_key, v.key_kind, epoch, signed.legacyWrapAllowed(v.id, epoch));
      } catch {
        warnings.push(`One vault couldn't be opened: its key may have been replaced. Ask the person who manages it to share it with you again.`);
        continue;
      }
    }
    opened.set(v.id, v);
    const status: ManifestStatus = manifestStatus.get(v.id) ?? "none";
    let name = "Vault";
    try {
      name = key.decryptMeta(v.id, v.meta).name ?? name;
    } catch {
      warnings.push(`Couldn't read the name of one of your vaults.`);
    }
    vaults.push({
      id: v.id,
      name,
      role: v.role,
      kind: v.key_kind,
      key,
      epoch: typeof v.key_epoch === "number" ? v.key_epoch : undefined,
      rosterSeq: verdict?.status === "ok" ? verdict.rosterSeq : typeof v.member_roster_seq === "number" ? v.member_roster_seq : 0,
      ...(verdict?.status === "ok" ? { trust: verdict.trust } : {}),
      ...(unresolved(status) ? { manifestWarning: true } : {}),
      ...(unresolved(status) && acceptableVaults.has(v.id) ? { manifestAcceptable: true } : {}),
      ...(unresolved(status) && acceptableVaults.has(v.id) && noRecordVaults.has(v.id) ? { manifestNoRecord: true } : {}),
      // Accepted without a record and none since: not checked, and it says so.
      ...(status === "none" && manifestSeq(v) === 0 && manifestMemoryFor(acct).notChecked(v.id) ? { manifestNotChecked: true } : {}),
    });
  }
  const byId = new Map(vaults.map((v) => [v.id, v]));
  // The vaults this device used: grandfathering at a later first signed sync covers only these (review M-B).
  signed.noteVaultsSeen(acct, [...byId.keys()]);
  const copies = new Map<string, { row: SyncItemRow; entry: VaultEntry | null }>();
  const items: VaultEntry[] = [];
  const failed = new Map<string, number>();
  const sealed = new Map<string, number>();
  const newer = new Set<string>();
  const unopenable: UnopenableItem[] = [];
  const revs = revMemoryFor(acct);
  const rollbacks = { kept: 0, shown: 0 };
  for (const served of snap.items.values()) {
    let row = served;
    const vault = byId.get(row.vault_id);
    if (!vault) continue;
    const old = decrypted.get(row.id);
    let entry: VaultEntry | null;
    if (old && kept.has(vault.key) && sameCiphertext(old.row, row)) {
      entry = old.entry;
      const deletedAt = row.deleted_at ?? null;
      if (entry && (entry.revision !== row.revision || entry.deletedAt !== deletedAt)) entry = { ...entry, revision: row.revision, deletedAt };
      // Still marked from an earlier sync: a kept newer copy holds the remembered counter, a served older one less.
      if (entry?.rollback) {
        if (revOf(entry.item) < (revs.get(entry.id) ?? 0)) rollbacks.shown++;
        else rollbacks.kept++;
      }
      if (!entry && newerRows.has(row.id)) newer.add(row.id);
    } else {
      const made = openRow(vault.key, row);
      if (typeof made !== "string") {
        // The copy to keep when the server sent an older one: what is shown, or what was last shown before the server
        // stopped sending the item.
        entry = checkRollback(revs, made, old?.entry ?? ghosts.get(row.id) ?? null, rollbacks);
      } else {
        // Only the key of an item this device already opened fails: the device goes on with the row it has (T1a).
        const have = made === "unopenable" ? heldCopy(row, old, ghosts.get(row.id)) : null;
        if (have) {
          entry = have.entry;
          row = { ...row, item_key: have.itemKey };
          snap.items.set(row.id, row);
          if (entry.rollback) {
            if (revOf(entry.item) < (revs.get(entry.id) ?? 0)) rollbacks.shown++;
            else rollbacks.kept++;
          }
        } else {
          entry = null;
          if (made === "newer") newer.add(row.id);
        }
      }
    }
    copies.set(row.id, { row, entry });
    if (entry) items.push(entry);
    else {
      failed.set(row.vault_id, (failed.get(row.vault_id) ?? 0) + 1);
      const status = manifestStatus.get(vault.id);
      if (newer.has(row.id)) {
        // It decrypted, so it is the vault's own: from an app newer than this one. Listed; only an owner or admin may
        // delete it for good (anyone who can write can add such rows, and they stop a key replacement).
        unopenable.push({
          id: row.id,
          vaultId: vault.id,
          deletedAt: row.deleted_at ?? null,
          deletable: mayDeleteNewer(vault.role) && !unchecked.has(vault.id) && !unresolved(status),
          kind: "newer",
        });
        continue;
      }
      sealed.set(row.vault_id, (sealed.get(row.vault_id) ?? 0) + 1);
      // Listed in its vault (or the trash) as an item that can't be opened, with the name this device last knew it by.
      // Someone who can edit may delete it for good while the vault's own record checks out (or it has none): nothing
      // of it has to be opened for that. The vault's other writes don't wait for it.
      const known = (old?.entry ?? ghosts.get(row.id))?.item.name;
      unopenable.push({
        id: row.id,
        vaultId: vault.id,
        deletedAt: row.deleted_at ?? null,
        deletable: vault.role !== "read" && !unchecked.has(vault.id) && !unresolved(status),
        kind: "unopenable",
        ...(typeof known === "string" && known ? { name: known } : {}),
      });
    }
  }
  for (const v of vaults) {
    const n = sealed.get(v.id);
    if (!n) continue;
    // A checked vault says so in a notice of its own (`VAULT_UNOPENABLE`); one without a record has only this line.
    if ((manifestStatus.get(v.id) ?? "none") !== "none") v.manifestUnopenable = true;
    else warnings.push(`${n === 1 ? "An item" : `${n} items`} in "${v.name}" can't be opened.`);
  }
  // Items that are no longer shown. An edit counter (and the copy kept for it) is forgotten only when the item's
  // absence is proven: it is missing from the vault it was in, and that vault's manifest checked out for this copy
  // (an own delete for good is forgotten where it is applied, `settle`). An item the server merely stopped sending
  // (left out of an answer, its vault hidden) keeps both, so an older copy served later is still told (review 5).
  const proven: string[] = [];
  for (const [id, was] of decrypted) {
    const now = copies.get(id);
    if (now) {
      // Shown again: no ghost. Served but no longer opening: the copy last shown is kept (its name, and as the newer
      // copy should the server send an older one that opens).
      if (now.entry) ghosts.delete(id);
      else if (was.entry) {
        ghosts.delete(id);
        ghosts.set(id, was.entry);
        if (ghosts.size > GHOSTS_MAX) ghosts.delete(ghosts.keys().next().value as string);
      }
      continue;
    }
    if (!snap.items.has(id) && byId.has(was.row.vault_id) && manifestStatus.get(was.row.vault_id) === "ok") {
      proven.push(id);
      ghosts.delete(id);
    } else if (was.entry) {
      ghosts.delete(id);
      ghosts.set(id, was.entry);
      if (ghosts.size > GHOSTS_MAX) ghosts.delete(ghosts.keys().next().value as string);
    }
  }
  revs.forget(proven);
  revs.flush();
  // Old trash is deleted here only after this device itself saw it in the trash for the retention period.
  trashSeenFor(acct).note(snap.items.values(), Math.floor(Date.now() / 1000));
  if (rollbacks.shown) warnings.push(ROLLBACK_SHOWN);
  else if (rollbacks.kept) warnings.push(ROLLBACK_KEPT);
  items.sort((a, b) => byName.compare(a.item.name, b.item.name));
  serverItems = items;
  decrypted = copies;
  openedFrom = opened;
  undecryptable = failed;
  unopenableRows = sealed;
  newerRows = newer;
  pinPersonalVault(snap.user.id, vaults);
  const names = new Map<string, string | null>();
  const invitations = openInvitations(snap.invitations, (inv) => {
    const cacheKey = `${inv.vault_id}\n${inv.wrapped_key}\n${inv.meta}`;
    let name = invitationNames.get(cacheKey);
    if (name === undefined) name = invitationName(acct, inv.vault_id, inv.wrapped_key, inv.meta);
    names.set(cacheKey, name);
    return name;
  }).map((inv) => {
    const trust = verdicts?.invitations.get(inv.vaultId);
    // Emails as compared and shown (`normalizeEmail`: a look-alike domain shows in punycode).
    const shown = inv.invitedBy ? { ...inv, invitedBy: { ...inv.invitedBy, email: signed.emailText(inv.invitedBy.email) } } : inv;
    return verdicts ? { ...shown, trust: trust ?? { kind: "refused" as const, reason: signed.CHECK_LATER } } : shown;
  });
  invitationNames = names;
  const changedKeys = new Map<string, KeyChange>();
  for (const b of blocked) if (b.changed) changedKeys.set(b.changed.identity.user_id, b.changed);
  for (const inv of invitations) if (inv.trust?.kind === "refused" && inv.trust.changed) changedKeys.set(inv.trust.changed.identity.user_id, inv.trust.changed);
  set({
    status: "unlocked",
    vaults,
    items: withChanges(items, vaults),
    offlineChanges: changes.changes,
    revision: snap.revision,
    warnings,
    invitations,
    blockedVaults: blocked,
    consents,
    keyChanges: [...changedKeys.values()],
    signingNotice: verdicts ? (signed.signingProblem() ?? signed.pinsNotice()) : null,
    unopenable,
    name: snap.user.name,
    emailVerified: snap.user.email_verified,
    pendingRotations: [
      ...new Set([
        ...readPendingRotations(snap.user.id).filter((id) => byId.has(id)),
        // Marked by the server when someone left or was removed without a key change; only admins can replace it.
        ...snap.vaults.filter((v) => v.rotation_pending && (v.role === "owner" || v.role === "admin")).map((v) => v.id),
      ]),
    ],
  });
  retryWhileWaiting();
  // Profile picture: fetched and opened only when its number changed (servers with `avatar`).
  void avatars.note(snap.user.avatar_seq, (sealed) => acct.openAvatar(sealed));
  // Handles the new state no longer uses (a vault gone, or its key replaced).
  before.forEach((v) => {
    if (!kept.has(v.key)) v.key.free();
  });
  // A vault came or went, or a key was replaced (on another device too): personal vaults may need new
  // emergency-access wraps. The first sync after unlocking runs the hook itself (`openVault`).
  if (before.length && vaultsMoved(before, vaults)) vaultKeysChanged();
}

// ---------------------------------------------------------- vault manifests

/** A vault's row in the copy (with the manifest of this app's own writes shown since). */
const vaultRow = (vaultId: string): SyncVaultRow | undefined => synced?.vaults.find((v) => v.id === vaultId);

/** `manifests` of a request body: one entry for each affected vault that has a manifest; nothing without any. */
const manifestsOf = (...entries: (ManifestEntry | null)[]) => {
  const list = entries.filter((m): m is ManifestEntry => m !== null).map(wireEntry);
  return list.length ? { manifests: list } : {};
};

/** A write into a vault whose check isn't finished (`unchecked`): it waits for a sync, like a write that met another. */
class Unchecked extends Error {
  constructor() {
    super(MANIFEST_UNCHECKED);
  }
}

/** Nothing was written and a sync may help: the vault changed meanwhile (`manifestRaced`), or its check isn't finished. */
const mustCatchUp = (e: unknown): boolean => manifestRaced(e) || e instanceof Unchecked;
/** The error after `MANIFEST_TRIES` such sends. */
const triesOver = (e: unknown): Error => new Error(e instanceof Unchecked ? MANIFEST_UNCHECKED : MANIFEST_BUSY);

/**
 * The manifest entry a write into `vaultId` carries: `removed` are the ids of the affected items (counted as the copy
 * holds them, before the write), `added` the items as they are after it. Null for a vault without a manifest: the
 * write is sent as before. Throws `MANIFEST_HELD` for a vault whose warning is unresolved (nothing is sent).
 */
function manifestFor(vaultId: string, key: core.VaultKey, removed: readonly string[], added: readonly ManifestRow[]): ManifestEntry | null {
  const status = manifestStatus.get(vaultId);
  if (unresolved(status)) throw new Error(MANIFEST_HELD);
  // Not checked yet (its manifest log couldn't be fetched, or this device's memory can't be read): no write goes out
  // before a sync checked the vault.
  if (unchecked.has(vaultId)) throw new Unchecked();
  const row = vaultRow(vaultId);
  if (!row || !manifestSeq(row)) return null;
  // A manifest this app never checked (not expected): nothing is built on it.
  if (status !== "ok") throw new Error(MANIFEST_HELD);
  const was = removed.map((id) => {
    const r = synced?.items.get(id);
    if (!r || r.vault_id !== vaultId) throw new Error(ITEM_GONE);
    return manifestRow(r);
  });
  return nextEntry(key, row, was, added);
}

/**
 * Send a write that carries a vault manifest. When the vault changed since this app's copy (409 `manifest_conflict`),
 * or got its first manifest meanwhile (400 `manifest_required`), nothing was written: sync (which checks the vault),
 * and send again, at most `MANIFEST_TRIES` times in all. `send` builds the request afresh on every call (from the
 * copy as it is then, so a vault that no longer checks out stops it with `MANIFEST_HELD`).
 */
async function manifestTries<T>(send: () => Promise<T>): Promise<T> {
  for (let sends = 1; ; sends++) {
    try {
      return await send();
    } catch (e) {
      if (!mustCatchUp(e)) throw e;
      if (sends >= MANIFEST_TRIES) throw triesOver(e);
      await catchUp();
    }
  }
}

let upkeepRunning = false;

/**
 * After a sync answer that was checked: start the first manifest of the vaults that may get one (`mayStart`), and
 * delete the trashed items that are due in vaults that have one (`mayPurge`; the server's sweeper leaves those vaults
 * to the apps). One attempt each, in the background; every failure is ignored (another device probably did it, and the
 * next sync decides again). Stops as soon as the copy is no longer the one the answer gave.
 */
async function manifestUpkeep(snap: Snapshot, gen: number): Promise<void> {
  if (upkeepRunning || !hasFeature(knownPublicConfig(), "vault_manifest")) return;
  upkeepRunning = true;
  try {
    let base = snap;
    for (const row of snap.vaults) {
      if (gen !== generation || synced !== base || state.status !== "unlocked" || !account) return;
      // Only vaults this sync opened: they passed the signed sharing checks.
      if (!state.vaults.some((v) => v.id === row.id)) continue;
      // Never while the vault's check isn't finished or this device's memory can't be read.
      const memory = manifestMemoryFor(account);
      if (memory.unreadable || unchecked.has(row.id)) continue;
      const status = manifestStatus.get(row.id) ?? "none";
      const rows = [...base.items.values()].filter((r) => r.vault_id === row.id);
      let next: Snapshot | null = base;
      if (mayStart(true, row, status, memory.get(row.id))) {
        // Not over an item the server sent older than this device saw it: the first manifest would seal that copy.
        if (serverItems.some((e) => e.vaultId === row.id && e.rollback)) continue;
        next = await startManifest(base, row, rows, gen);
      } else if (mayPurge(row, status)) next = await purgeDue(base, row, rows, gen);
      if (!next) return;
      base = next;
    }
  } catch {
    /* one attempt: the next sync decides again */
  } finally {
    upkeepRunning = false;
  }
}

type ManifestAnswer = { vault_seq?: unknown; manifest_seq?: unknown; manifest_link?: unknown } | null;

/**
 * Show a manifest this app just stored for a vault (a first one, a baseline) without asking the server, when its
 * answer says it is the vault's and the copy is still the one it was computed from; otherwise sync. Returns the copy
 * after it, or null when a sync was asked for instead.
 */
function ownManifestStored(base: Snapshot, vaultId: string, sent: ManifestEntry, answer: ManifestAnswer, gen: number): Snapshot | null {
  if (gen !== generation) return null;
  if (synced !== base || state.status !== "unlocked" || answer?.manifest_seq !== sent.seq || !linkStored(sent, answer.manifest_link) || typeof answer.vault_seq !== "number") {
    sync().catch(() => {});
    return null;
  }
  const next = applyOwnManifest(base, vaultId, sent, answer.vault_seq);
  synced = next;
  rememberManifest(vaultId, sent);
  settleVerdict(vaultId);
  materialize(next);
  return next;
}

/**
 * A vault's verdict once its manifest is one this device made or accepted for exactly the rows held ("ok"), or once
 * the user accepted that the server shows none ("none"). A row that doesn't open keeps its notice either way
 * (`materialize`); it is no part of the verdict.
 */
function settleVerdict(vaultId: string, status: "ok" | "none" = "ok") {
  acceptableVaults.delete(vaultId);
  noRecordVaults.delete(vaultId);
  manifestStatus.set(vaultId, status);
}

/** The body of `PUT /vaults/{id}/manifest`: a first manifest (`baseSeq` 0) or a baseline, pinned to the vault's number. */
const manifestPut = (m: ManifestEntry, baseSeq: number, vaultSeq: number) => ({ base_seq: baseSeq, seq: m.seq, prev: m.prev, sealed: m.sealed, vault_seq: vaultSeq });

/** A vault's first manifest (version 1, replacing none) over exactly the rows of `base`, which must still be the vault's when it is stored. */
async function startManifest(base: Snapshot, row: SyncVaultRow, rows: SyncItemRow[], gen: number): Promise<Snapshot | null> {
  if (typeof row.key_epoch !== "number" || typeof row.seq !== "number" || rows.some((r) => typeof r.data !== "string")) return base;
  // Every row decrypts with the vault's key: a manifest is never started over a row that doesn't. (A row that
  // decrypts but holds an item from a newer app is the vault's own and is counted like any other.)
  if (unopenableRows.get(row.id)) return base;
  const m = startEntry(vaultFor(row.id).key, row.id, row.key_epoch, 1, null, rows.map(manifestRow));
  const answer = await api<ManifestAnswer>(`/vaults/${row.id}/manifest`, { method: "PUT", body: manifestPut(m, 0, row.seq) });
  return ownManifestStored(base, row.id, m, answer, gen);
}

/**
 * Delete for good the trashed items of a vault that are due (`dueTrash`: the server's clock and retention, and this
 * device's own record of how long it has seen each item in the trash), as one vault write: one request of at most
 * the server's `max_import_items` items (250 at most) for each vault and sync answer, tried once. More that is due
 * goes after a later sync. An answer that isn't exactly the expected next state ends it with a sync.
 */
async function purgeDue(base: Snapshot, row: SyncVaultRow, rows: SyncItemRow[], gen: number): Promise<Snapshot | null> {
  if (!account) return null;
  const seen = trashSeenFor(account);
  const due = dueTrash(rows, base.serverTime, base.trashDays, seen.get, Math.floor(Date.now() / 1000));
  if (!due.length) return base;
  const perRequest = Math.min(IMPORT_BATCH, positive(knownPublicConfig()?.limits?.max_import_items) ?? IMPORT_BATCH);
  const chunk = due.slice(0, perRequest);
  const entry = manifestFor(row.id, vaultFor(row.id).key, chunk.map((r) => r.id), []);
  if (!entry) return base;
  const known = knownSeq(base, row.id);
  const answer = await api<ManifestAnswer>(`/vaults/${row.id}/trash/purge`, {
    body: { items: chunk.map((r) => ({ id: r.id, revision: r.revision })), ...manifestsOf(entry) },
  });
  if (gen !== generation) return null;
  const apply =
    synced === base &&
    state.status === "unlocked" &&
    afterWrite(known, answer?.vault_seq, true, { sent: entry.seq, answered: answer?.manifest_seq, sentLink: entry.link, answeredLink: answer?.manifest_link }) === "apply";
  if (!apply || typeof answer?.vault_seq !== "number") {
    sync().catch(() => {});
    return null;
  }
  const items = new Map(base.items);
  for (const r of chunk) items.delete(r.id);
  const next = applyOwnManifest({ ...base, items }, row.id, entry, answer.vault_seq);
  synced = next;
  rememberManifest(row.id, entry);
  // Deleted for good by this device: their edit counters go with them.
  revMemoryFor(account).forget(chunk.map((r) => r.id));
  materialize(next);
  return next;
}

/**
 * "Use the server's copy": accept an unresolved vault as the server has it now, after the user confirmed it. The
 * whole account is fetched afresh; if the vault checks out then, there is nothing to accept. Otherwise:
 *
 * - The served copy is consistent in itself (`acceptVault`: its record matches its items with nothing remembered, or
 *   it shows no record): this device takes that as what it remembers from now on, also when it remembered a later
 *   version (the state after a restored backup, or after someone else's baseline). Nothing is written to the server,
 *   so every member can do it, also one who can only read.
 * - It isn't: someone who can edit stores a new record (a baseline) over exactly the served rows, always one version
 *   above the row's, naming the manifest the server shows as the one it replaces (its link from the row's fields: it
 *   needn't be one this device can open). This device then remembers that record, whatever it remembered before.
 *   Other devices follow it by themselves when they are on the history under it; the rest accept it as above.
 *
 * Items of the vault that this device had seen newer are accepted as served with it (the user accepted "anything that
 * is missing, restored or out of date"): the marks, the newer copies kept and the edit counters of the items this
 * device held in that vault before the fetch (never of an id the fetch newly places there). An item that can't be
 * opened keeps its notice after both; it is no part of this.
 *
 * When the server shows no record at all for a vault this device remembers one for, accepting means forgetting that
 * memory: from then on nothing is checked for the vault until a new record is started. That needs a confirmation of
 * its own (`USE_SERVER_COPY_NO_RECORD_BODY`): unless `noRecord` says the user gave it, nothing is forgotten and
 * "confirm_no_record" is returned (the vault then carries `manifestNoRecord`, also when the server showed a record
 * when the user first asked). Afterwards the vault is marked as not checked (`Vault.manifestNotChecked`).
 */
export async function acceptServerCopy(vaultId: string, opts: { noRecord?: boolean } = {}): Promise<"done" | "confirm_no_record"> {
  const gen = generation;
  // The items this device holds in the vault now, before anything is fetched: only their marks go with the acceptance.
  const mine = new Set<string>();
  for (const [id, held] of decrypted) if (held.row.vault_id === vaultId) mine.add(id);
  for (const [id, ghost] of ghosts) if (ghost.vaultId === vaultId) mine.add(id);
  for (let attempt = 1; ; attempt++) {
    // A whole answer taken over after this was asked for: never the copy held from before (review Info 12).
    let before = wholeAdoptions;
    fullNext = true;
    await sync();
    if (gen === generation && wholeAdoptions === before && account) {
      // A sync that was already on its way took the request for a whole answer, or its answer was dropped: once more.
      before = wholeAdoptions;
      fullNext = true;
      await sync();
    }
    if (gen !== generation || state.status !== "unlocked" || !account) throw new Error(LOCKED);
    if (wholeAdoptions === before) throw new Error(ACCEPT_NO_ANSWER);
    const base = synced;
    const row = vaultRow(vaultId);
    const v = state.vaults.find((x) => x.id === vaultId);
    if (!base || !row || !v) throw new Error("Vault not found.");
    // A later answer checked out: nothing to accept.
    if (!unresolved(manifestStatus.get(vaultId))) return "done";
    const memory = manifestMemoryFor(account);
    if (memory.unreadable) throw new Error(MANIFEST_UNCHECKED);
    const rows = [...base.items.values()].filter((r) => r.vault_id === vaultId);
    const local = acceptVault(v.key, row, rows);
    if (local.status !== "mismatch") {
      // No record served: the user has to have confirmed that checking stops (the text for it), or is asked now.
      if (local.status === "none" && !opts.noRecord) return "confirm_no_record";
      // Consistent in itself: remembered from now on (or forgotten, when the server shows no record). No request.
      const done = local.status === "ok" ? memory.replace(vaultId, local.version, local.link) : memory.forget(vaultId);
      if (!done) throw new Error(MANIFEST_UNCHECKED);
      ownMoves++;
      acceptItemRevs(v.key, rows, mine);
      settleVerdict(vaultId, local.status);
      materialize(base);
      return "done";
    }
    if (v.role === "read") throw new Error(VAULT_WARNING_READER);
    if (typeof row.key_epoch !== "number" || typeof row.seq !== "number" || rows.some((r) => typeof r.data !== "string")) throw new Error(UNEXPECTED_SYNC);
    let m: ManifestEntry;
    try {
      m = startEntry(v.key, vaultId, row.key_epoch, baselineSeq(row), rowLink(row), rows.map(manifestRow));
    } catch {
      // The row's manifest fields aren't a manifest's, or a row is no item row (a trash time that is no time).
      throw new Error(UNEXPECTED_SYNC);
    }
    let answer: ManifestAnswer;
    try {
      answer = await api<ManifestAnswer>(`/vaults/${vaultId}/manifest`, { method: "PUT", body: manifestPut(m, manifestSeq(row), row.seq) });
    } catch (e) {
      if (hasErrorCode(e, "manifest_not_ready")) throw new Error(MANIFEST_NOT_READY);
      // At most 10 baselines an hour for each member and vault (429, the usual message): the warning stays, no retry.
      if (!hasErrorCode(e, "manifest_conflict")) throw e;
      if (attempt >= MANIFEST_TRIES) throw new Error(MANIFEST_BUSY);
      continue;
    }
    if (gen !== generation || !account) return "done";
    // Not the record this device sent (not expected): nothing is remembered, the next sync judges what is there.
    if (answer?.manifest_seq !== m.seq || !linkStored(m, answer.manifest_link)) {
      await sync();
      return "done";
    }
    // Stored: this device's memory is that record from now on, whatever it held (also a later version).
    if (!manifestMemoryFor(account).replace(vaultId, m.seq, m.link)) throw new Error(MANIFEST_UNCHECKED);
    ownMoves++;
    if (synced === base && state.status === "unlocked" && typeof answer.vault_seq === "number") {
      const next = applyOwnManifest(base, vaultId, m, answer.vault_seq);
      synced = next;
      acceptItemRevs(v.key, rows, mine);
      settleVerdict(vaultId);
      materialize(next);
    } else await sync();
    return "done";
  }
}

/**
 * With an accepted copy of a vault: its items as served are what this device saw from now on. An item marked as older
 * than this device remembered loses the mark (and the newer copy kept for it): its counter becomes the served one.
 * Only for `mine`, the items this device held in that vault before the accepted answer was fetched: an id the answer
 * newly lists under the vault (another vault's item, say) keeps its counter and its mark.
 */
function acceptItemRevs(key: core.VaultKey, rows: readonly SyncItemRow[], mine: ReadonlySet<string>) {
  if (!account) return;
  const revs = revMemoryFor(account);
  for (const row of rows) {
    if (!mine.has(row.id)) continue;
    const held = decrypted.get(row.id);
    if (!held?.entry?.rollback && !ghosts.has(row.id)) continue;
    const served = decryptRow(key, row);
    if (!served) continue;
    revs.accept(row.id, revOf(served.item));
    decrypted.delete(row.id);
    ghosts.delete(row.id);
  }
  revs.flush();
}

/**
 * Delete for good a row that can't be opened (`State.unopenable`): nothing of it has to be read, the vault's next
 * manifest counts it out by the row as the server sent it. Live or in the trash, one request. Only for a row that
 * really doesn't decrypt: never one this device shows (also from a copy it opened before, when only the served key
 * fails). A row that holds an item from a newer app only for the vault's owners and admins. A vault whose record doesn't check out needs
 * `acceptServerCopy` first. When the vault changed meanwhile the request is built again from a fresh sync, at most
 * `MANIFEST_TRIES` times. Ends with a sync, which lifts the notice once no such row is left.
 */
export async function purgeUnopenable(id: string): Promise<void> {
  requireWritableServer();
  const gen = generation;
  for (let sends = 1; ; sends++) {
    if (gen !== generation || state.status !== "unlocked" || !account) throw new Error(LOCKED);
    const row = synced?.items.get(id);
    // Gone already (another device deleted it).
    if (!row) return;
    const v = state.vaults.find((x) => x.id === row.vault_id);
    const vault = vaultRow(row.vault_id);
    if (!v || !vault) throw new Error(ITEM_GONE);
    // Only a row that really doesn't open: everything else is deleted the ordinary way.
    if (decrypted.get(id)?.entry) throw new Error(ITEM_GONE);
    // It decrypts: an item from a newer app. Only an owner or admin deletes it from here.
    if (newerRows.has(id) && !mayDeleteNewer(v.role)) throw new Error(NEWER_ITEM_NOTE);
    if (v.role === "read") throw new Error("Only someone who can edit this vault can do this.");
    try {
      if (unchecked.has(v.id)) throw new Unchecked();
      let manifest: ManifestEntry | null = null;
      if (manifestSeq(vault)) {
        const status = manifestStatus.get(v.id);
        // The vault's record must check out for the rows held.
        if (status !== "ok") throw new Error(MANIFEST_HELD);
        manifest = nextEntry(v.key, vault, [manifestRow(row)], []);
      } else if (unresolved(manifestStatus.get(v.id))) throw new Error(MANIFEST_HELD);
      const params = manifest ? [`revision=${row.revision}`, ...manifestQuery(manifest)] : [];
      await api<WriteAnswer>(withQuery(`/items/${id}/permanent`, params), { method: "DELETE" });
    } catch (e) {
      if (!mustCatchUp(e) && !revisionConflict(e)) throw e;
      if (sends >= MANIFEST_TRIES) throw triesOver(e);
      await catchUp();
      continue;
    }
    if (gen !== generation) return;
    ghosts.delete(id);
    if (account) {
      const revs = revMemoryFor(account);
      revs.forget([id]);
      revs.flush();
    }
    // The sync checks the vault again: without such rows its warning goes.
    await sync();
    return;
  }
}

/**
 * "Reset on this device": this device's record of the vaults' manifests can't be read (`State.deviceRecordUnreadable`).
 * The unreadable record is moved aside and the device goes on as one that remembers nothing: it trusts what the
 * server shows at the sync that follows, and starts a new record from it. The user confirmed it.
 */
export async function resetDeviceRecord(): Promise<void> {
  if (!account || state.status !== "unlocked") throw new Error(LOCKED);
  manifestMemoryFor(account).reset();
  unreadableWhole = false;
  if (state.deviceRecordUnreadable) set({ deviceRecordUnreadable: false });
  fullNext = true;
  await sync();
}

/** Whether two vault lists differ in their vaults or in a vault's key epoch. */
function vaultsMoved(before: readonly Vault[], after: readonly Vault[]): boolean {
  if (before.length !== after.length) return true;
  const epochs = new Map(before.map((v) => [v.id, v.epoch]));
  return after.some((v) => !epochs.has(v.id) || epochs.get(v.id) !== v.epoch);
}

/**
 * The name of a vault offered in an invitation: its key, sealed to this account, is opened for that alone and freed at
 * once (nothing of the vault is read or kept before the user accepts). Null when it can't be opened.
 */
function invitationName(acct: core.Account, vaultId: string, sealed: string, meta: string): string | null {
  let key: core.VaultKey;
  try {
    key = acct.openVaultKey(vaultId, sealed, "sealed", 0, false);
  } catch {
    return null;
  }
  try {
    const name = cleanText((key.decryptMeta(vaultId, meta) as { name?: unknown } | null)?.name);
    return name || "Shared vault";
  } catch {
    return null;
  } finally {
    key.free();
  }
}

/** The name of a vault needing consent (a sealed key, opened for that alone). */
function consentName(acct: core.Account, v: SyncVaultRow): string | null {
  return v.key_kind === "sealed" ? invitationName(acct, v.id, v.wrapped_key, v.meta) : null;
}

/**
 * A live-sync message: sync only when it announces something this client doesn't have yet (`noticeAction`). With
 * delta sync, a sync already on its way may bring it, so that one is waited for before deciding.
 */
async function onSyncNotice(msg: SyncNotice) {
  if (!deltaOn) {
    if (noticeAction(msg, () => undefined, state.revision, false) === "sync") sync().catch(() => {});
    return;
  }
  const pending = running;
  if (pending) await pending.catch(() => {});
  if (state.status !== "unlocked") return;
  if (noticeAction(msg, (id) => knownSeq(synced, id), state.revision, true) === "sync") sync().catch(() => {});
}

/** This session's live-sync origin (the socket's `hello`), or null while not connected. Every tab of the session shares it. */
export const liveSyncOrigin = (): string | null => liveOrigin;

/**
 * Live-sync news for other parts of the app (`device-login-client.ts`): a new connection (`connected`), a device asking
 * to sign in to the account (`auth_request`) and a request answered by any app (`auth_request_answered`).
 */
export type LiveNotice = { type: "connected" } | { type: "auth_request" | "auth_request_answered"; id: string };
const liveListeners = new Set<(n: LiveNotice) => void>();

/** Run `fn` for every live-sync notice; returns the unsubscribe. */
export function onLiveNotice(fn: (n: LiveNotice) => void) {
  liveListeners.add(fn);
  return () => {
    liveListeners.delete(fn);
  };
}

function emitLive(n: LiveNotice) {
  liveListeners.forEach((fn) => {
    try {
      fn(n);
    } catch {
      /* a listener's failure is its own, never the socket's */
    }
  });
}

/** Reconnect delay: 3 s after a healthy connection drops, doubling to 2 min while the server stays unreachable. */
const RECONNECT_MIN = 3000;
const RECONNECT_MAX = 120_000;
let reconnectDelay = RECONNECT_MIN;
let onlineListener: (() => void) | null = null;

function connectSocket() {
  socket?.close();
  const t = getTokens();
  // The server refuses live sync until two-step login is set up (`continueAfterTwoStep` connects).
  if (!t || state.status === "two-step") return;
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    // Offline: don't hammer the network; reconnect when the browser/OS reports a connection again.
    if (!onlineListener && typeof window !== "undefined") {
      onlineListener = () => {
        window.removeEventListener("online", onlineListener!);
        onlineListener = null;
        if (state.status === "unlocked") connectSocket();
      };
      window.addEventListener("online", onlineListener);
    }
    return;
  }
  const ws = new WebSocket(server.wsUrl(`/ws?access_token=${encodeURIComponent(t.access)}`));
  socket = ws;
  liveOrigin = null;
  ws.onopen = () => {
    reconnectDelay = RECONNECT_MIN;
    // Anything announced while this app wasn't connected (sign-in requests) is listed again.
    if (socket === ws) emitLive({ type: "connected" });
  };
  ws.onmessage = (e) => {
    let msg: { type?: string; origin?: unknown; id?: unknown } | null;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (!msg || typeof msg !== "object") return;
    // Remembered, but never a reason to skip a message: every tab and window of this session shares it.
    if (msg.type === "hello" && socket === ws) liveOrigin = typeof msg.origin === "string" ? msg.origin : null;
    if (msg.type === "sync") void onSyncNotice(msg as SyncNotice);
    if (msg.type === "logout") confirmSignedOut();
    // The admin now requires two-step login and the account has no method yet: the server closes the connection next.
    if (isTwoStepNotice(msg) && socket === ws) enterTwoStepGate();
    if ((msg.type === "auth_request" || msg.type === "auth_request_answered") && typeof msg.id === "string" && socket === ws) emitLive({ type: msg.type, id: msg.id });
  };
  ws.onclose = (e) => {
    // Closed because two-step login is required first (policy): the gate shows, and nothing reconnects until a method
    // is set up (`continueAfterTwoStep`), as after a 403 `two_step_required`.
    if (socket === ws && isTwoStepClose(e.code, e.reason)) return enterTwoStepGate();
    if (socket !== ws || state.status !== "unlocked") return;
    // Reconnect after the access token has had a chance to refresh; back off while the server is unreachable
    // (a desktop app in the tray would otherwise retry every few seconds all night). `resync()` on wake/focus
    // reconnects at once regardless of the delay.
    const delay = reconnectDelay + Math.random() * 1000;
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX);
    setTimeout(() => {
      if (state.status === "unlocked" && socket === ws) {
        api<{ revision: number }>("/sync/revision")
          .then((r) => (r.revision !== state.revision ? sync() : undefined))
          .catch(() => {})
          .finally(() => {
            if (state.status === "unlocked" && socket === ws) connectSocket();
          });
      }
    }, delay);
  };
}

/**
 * Desktop: after sleep, a network change or on the background-sync timer. The live connection can die without a
 * close event, so the server is asked for its revision first (which also refreshes an expired access token),
 * the connection is reopened and the vault synced if the server has anything newer. A no-op while locked.
 */
export async function resync(): Promise<void> {
  if (state.status !== "unlocked") return;
  const r = await api<{ revision: number }>("/sync/revision");
  if (state.status !== "unlocked") return;
  reconnectDelay = RECONNECT_MIN;
  connectSocket();
  // Higher: something new. Lower: the server went back (a restored backup); the sync judges it (`fetchSync`).
  if (r.revision !== state.revision) await sync();
  else kickSender();
}

// -------------------------------------------------------------- save target

const personalKey = (userId: string) => `pa.personal.${userId}`;

/**
 * Remember the user's own vault. Only a vault wrapped with the user's account key ("account")
 * can be one they created; a shared ("sealed") vault is never chosen automatically, because
 * whoever shared it holds its key.
 */
function pinPersonalVault(userId: string, vaults: Vault[]) {
  const pinned = read(personalKey(userId));
  const own = vaults.filter((v) => v.kind === "account" && v.role === "owner");
  if (pinned && own.some((v) => v.id === pinned)) return;
  if (own[0]) store(personalKey(userId), own[0].id);
}

/** Where new items go unless the user picks another vault: their own vault, never a shared one. */
export function defaultVaultId(): string {
  const pinned = read(personalKey(state.userId));
  const own = state.vaults.filter((v) => v.kind === "account" && v.role === "owner");
  return own.find((v) => v.id === pinned)?.id ?? own[0]?.id ?? "";
}

// ------------------------------------------------------------------- items

const LOCKED = "The vault is locked. Unlock it and try again.";
const KEY_CHANGED_AGAIN = "Someone replaced this vault's key just now. Try again.";
const CHANGED_ELSEWHERE =
  "This item was changed on another device or by someone you share the vault with, so your changes weren't saved. Choose which version to keep, then save again.";
const ITEM_GONE = "This item is no longer in your vault. It may have been deleted on another device.";

/** A vault with its key handle and that key's epoch, read together: both come from the same /sync. */
function vaultFor(vaultId: string): Vault {
  const v = state.vaults.find((x) => x.id === vaultId);
  if (!v) throw new Error(state.status === "unlocked" ? "Vault not found." : LOCKED);
  return v;
}

/** `key_epoch` for a body encrypted with (or wrapping) `v.key`; nothing for servers without key epochs. */
const epochOf = (v: Vault | undefined) => (v?.epoch === undefined ? {} : { key_epoch: v.epoch });

/** 409 vault_key_changed: the vault's key was replaced after our last sync, and nothing was written. */
const keyChanged = (e: unknown) => hasErrorCode(e, "vault_key_changed");
/** 409: the item's revision isn't the one the edit started from. */
const revisionConflict = (e: unknown) => hasErrorCode(e, "revision_conflict", "item changed on another device; sync and retry");
/** 409: a create named an id that already exists (with other content, on servers that accept repeated creates). */
const itemExists = (e: unknown) => hasErrorCode(e, "item_exists", "item id already exists");
/** Worth another try after a pause: no connection, the server failing for a moment, or too many requests. */
const transient = (e: unknown) => e instanceof UnreachableError || (e instanceof ApiError && (e.status === 429 || (e.status >= 500 && !isOutOfStorage(e))));

/** Sync after the server reported newer data (a new vault key, a newer item); fails when the vault was locked meanwhile. */
async function catchUp() {
  await sync();
  if (state.status !== "unlocked") throw new Error(LOCKED);
}

/**
 * What item writes answer: the item's new revision, with delta sync the vault's number after the write, and the
 * vault's manifest version after it (0: none).
 */
type WriteAnswer = { revision?: unknown; vault_seq?: unknown; manifest_seq?: unknown; manifest_link?: unknown } | null;

/**
 * After one of this client's item writes, update the vault with the least work. Without delta sync: a sync, as
 * before. With it, the write's `vault_seq` says whether anything else happened in the vault (`afterWrite`): a number
 * this client already has means a sync since brought the write (nothing to do); exactly the next number means the
 * write was the only change, so `own()` (the row as the server stored it, when this client knows it) is shown
 * without asking; anything else is a delta sync. A sync that was already asking before the write was answered may
 * not include it, so it is waited for before deciding.
 *
 * `sent`: the vault manifest the write carried (null: none). The write is shown without asking only when the answer's
 * `manifest_link` is that manifest's link (and `manifest_seq` its version): the vault row then holds that manifest,
 * and it is remembered. Otherwise (a request sent again whose first try was stored under another manifest, another
 * device's write) the sync that follows checks the vault, and nothing of what was sent is remembered.
 */
async function settle(vaultId: string | undefined, answer: WriteAnswer, own?: (vaultSeq: number) => OwnWrite | null, sent: ManifestEntry | null = null): Promise<void> {
  const gen = generation;
  const vaultSeq = answer?.vault_seq;
  if (!deltaOn || !vaultId || typeof vaultSeq !== "number") return sync();
  const pending = running;
  if (pending) await pending.catch(() => {});
  if (gen !== generation) return;
  const action = afterWrite(knownSeq(synced, vaultId), vaultSeq, !!own, {
    sent: sent?.seq,
    answered: answer?.manifest_seq,
    ...(sent ? { sentLink: sent.link, answeredLink: answer?.manifest_link } : {}),
  });
  if (action === "none") return;
  if (action === "apply" && own && synced && state.status === "unlocked") {
    const write = own(vaultSeq);
    if (write) {
      synced = applyOwnWrite(synced, sent ? { ...write, manifest: { seq: sent.seq, sealed: sent.sealed, prev: sent.prev } } : write);
      if (sent) rememberManifest(vaultId, sent);
      else ownMoves++;
      materialize(synced);
      return;
    }
  }
  return sync();
}

/**
 * The row the server stored for an item this client just sent (`enc`): `base` is its row before the write (edits keep
 * its trash state). Row times are the server's own; nothing reads them, and the next delta brings the stored ones.
 */
function storedRow(enc: EncryptedItem, answer: WriteAnswer, base: SyncItemRow | null): SyncItemRow | null {
  if (typeof answer?.revision !== "number") return null;
  const now = Math.floor(Date.now() / 1000);
  return { id: enc.id, vault_id: enc.vault_id, item_key: enc.key, data: enc.data, revision: answer.revision, deleted_at: base?.deleted_at ?? null, created_at: base?.created_at ?? now, updated_at: now };
}

/** The vault an item is in, read before a write that names only the item. */
const vaultOf = (id: string): string | undefined => synced?.items.get(id)?.vault_id ?? serverItems.find((x) => x.id === id)?.vaultId;

/**
 * Send a write encrypted with a vault key. When the server has replaced that key since our last sync (409
 * vault_key_changed, nothing written), sync, which brings the new key, and send it once more. `send` must look the
 * vault up again on every call: the sync frees the old key handles.
 */
async function withCurrentKey<T>(send: () => Promise<T>): Promise<T> {
  try {
    return await send();
  } catch (e) {
    if (!keyChanged(e)) throw e;
  }
  await catchUp();
  try {
    return await send();
  } catch (e) {
    throw keyChanged(e) ? new Error(KEY_CHANGED_AGAIN) : e;
  }
}

/** Vaults the user can write to, their own vault first. */
export function writableVaults() {
  const first = defaultVaultId();
  return state.vaults.filter((v) => v.role !== "read").sort((a, b) => (a.id === first ? -1 : b.id === first ? 1 : 0));
}

/** A new item id. The editor keeps one per new item, so saving again after a failure can't make a second copy. */
export const newItemId = (): string => core.newId();

/**
 * Save a new item. When trying again after a failure, pass the same `id`: if the earlier try was saved and only its
 * answer got lost, the item is updated with this content instead of being saved twice.
 */
export async function createItem(vaultId: string, item: Item, id: string = newItemId()): Promise<string> {
  requireWritableServer();
  const now = Math.floor(Date.now() / 1000);
  const data = { ...item, created_at: now, updated_at: now };
  if (!offlineOn()) return postItem(vaultId, data, id);
  const waitAs = (sent: SentBody | null) => queueChange({ kind: "create", vault_id: vaultId, item_id: id, base_revision: null, item: data, sent });
  if (knownOffline()) {
    vaultFor(vaultId);
    await waitAs(null);
    return id;
  }
  let body: SentBody | null = null;
  try {
    return await postItem(vaultId, data, id, async (b) => {
      body = b;
    });
  } catch (e) {
    if (!waitsAfter(failureOf(e))) throw e;
    noteOffline();
    await waitAs(body);
    return id;
  }
}

/**
 * POST a new item (`data` as it is to be stored). `onBody` gets the body's encrypted part before each request is sent
 * (the offline sender keeps it as `sent`). An id that exists already with other content: the earlier try is
 * overwritten (`dedupe`, the editor's retry), or `item_exists` is thrown (the offline sender decides itself).
 */
async function postItem(vaultId: string, data: Item, id: string, onBody?: (b: SentBody) => Promise<void>, dedupe = true): Promise<string> {
  let sent: { enc: EncryptedItem; answer: WriteAnswer; manifest: ManifestEntry | null };
  try {
    sent = await manifestTries(() =>
      withCurrentKey(async () => {
        const v = vaultFor(vaultId);
        const enc = v.key.encryptItem(data, id, vaultId) as EncryptedItem;
        const manifest = manifestFor(vaultId, v.key, [], [{ id, deleted_at: null, data: enc.data }]);
        await onBody?.({ key: enc.key, data: enc.data, key_epoch: v.epoch ?? null });
        return { enc, manifest, answer: await api<WriteAnswer>("/items", { body: { ...enc, ...epochOf(v), ...manifestsOf(manifest) } }) };
      }),
    );
  } catch (e) {
    if (!dedupe || !itemExists(e)) throw e;
    // An earlier try with this id was saved. This try was encrypted afresh, so the server can't tell it's the same
    // item: save this content over the saved one.
    await catchUp();
    const saved = serverItems.find((x) => x.id === id);
    if (!saved) throw e;
    await saveOver(saved, { ...data, created_at: saved.item.created_at }, vaultId);
    return id;
  }
  await settle(
    vaultId,
    sent.answer,
    (vaultSeq) => {
      const row = storedRow(sent.enc, sent.answer, null);
      return row && { kind: "upsert", row, vaultSeq };
    },
    sent.manifest,
  );
  return id;
}

export async function updateItem(entry: VaultEntry, item: Item, vaultId = entry.vaultId) {
  const now = Math.floor(Date.now() / 1000);
  const old = entry.item.login?.password;
  const next = { ...item, updated_at: now };
  if (next.login && old && old !== next.login.password && next.password_history[0]?.password !== old) {
    next.password_history = [{ password: old, changed_at: now }, ...next.password_history].slice(0, 20);
  }
  if (!offlineOn()) return saveOver(entry, next, vaultId);
  requireWritableServer();
  // A change of this item that is being sent right now finishes first (its outcome decides where this one goes).
  await flightOf(entry.id);
  const move = vaultId !== entry.vaultId;
  const pending = changeFor(changes, entry.id);
  if (pending || knownOffline()) {
    // Moves need a connection; an item with a change waiting takes no move until that change is sent or decided.
    if (move) throw new Error(pending ? HAS_CHANGE : NEEDS_CONNECTION);
    return queueChange({ kind: "edit", vault_id: entry.vaultId, item_id: entry.id, base_revision: entry.revision, item: next });
  }
  // An item created on this device and sent meanwhile: the edit starts from the server's copy of it.
  const base = entry.enc.key ? entry : (serverItems.find((x) => x.id === entry.id) ?? entry);
  let body: SentBody | null = null;
  try {
    await saveOver(base, next, vaultId, async (b) => {
      body = b;
    });
  } catch (e) {
    if (move || !waitsAfter(failureOf(e))) throw e;
    noteOffline();
    await queueChange({ kind: "edit", vault_id: base.vaultId, item_id: base.id, base_revision: base.revision, item: next, sent: body });
  }
}

/** `putItem`, then show the result. A move changes two vaults but answers only the target's number: never shown as sent. */
async function saveOver(base: VaultEntry, next: Item, vaultId: string, onBody?: (b: SentBody) => Promise<void>) {
  requireWritableServer();
  const sent = await putItem(base, next, vaultId, onBody);
  // An earlier try had been stored: the sync that found out already shows it.
  if (!sent) return;
  const own =
    sent.from === vaultId
      ? (vaultSeq: number): OwnWrite | null => {
          const before = synced?.items.get(sent.enc.id);
          const row = before?.vault_id === vaultId ? storedRow(sent.enc, sent.answer, before) : null;
          return row && { kind: "upsert", row, vaultSeq };
        }
      : undefined;
  await settle(vaultId, sent.answer, own, sent.manifest);
}

/** JSON with object keys sorted, to compare items whatever order their fields were set in. */
function canonical(item: Item, ignore: string[] = []): string {
  const sort = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sort)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, sort((v as Record<string, unknown>)[k])]),
          )
        : v;
  const copy: Record<string, unknown> = { ...item };
  ignore.forEach((k) => delete copy[k]);
  return JSON.stringify(sort(copy));
}

/** Only the item's encryption or revision changed (e.g. its vault key was replaced), not its content or place. */
function sameItem(a: VaultEntry, b: VaultEntry) {
  // `rev` is the core's edit counter: re-encrypting (a new vault key) counts it up without changing the content.
  return a.vaultId === b.vaultId && a.deletedAt === b.deletedAt && canonical(a.item, ["rev"]) === canonical(b.item, ["rev"]);
}

/** The server already holds `next` in `vaultId`: an earlier try of this save was stored, only its answer got lost. */
function holds(entry: VaultEntry, next: Item, vaultId: string) {
  // updated_at is set per try, and the core stamps `format` and counts `rev` when it encrypts.
  const ignore = ["updated_at", "format", "rev"];
  return entry.vaultId === vaultId && canonical(entry.item, ignore) === canonical(next, ignore);
}

/**
 * PUT `next` over `base` (into `vaultId`; another vault moves it) with the revision the edit started from. When the
 * server has newer data (a new vault key, or a newer revision), sync: if only the item's encryption changed, send it
 * again on top of the new version; if its content changed, stop, so nobody's change is overwritten unseen (the
 * synced vault shows the newer version, and the editor offers to keep or discard the user's changes).
 *
 * Vault manifests: an edit carries its vault's next manifest (the stored row out, the new `data` in, same trash state);
 * a move one for the vault it leaves (the stored row out) and one for the vault it enters (the re-encrypted row in),
 * each only when that vault has a manifest. When a vault changed meanwhile (`manifestRaced`) the same sync and checks
 * follow, and the edit is sent again while the item itself is unchanged, at most `MANIFEST_TRIES` sends in all. The
 * returned `manifest` is the item's (new) vault's.
 */
async function putItem(
  base: VaultEntry,
  next: Item,
  vaultId: string,
  onBody?: (b: SentBody) => Promise<void>,
): Promise<{ enc: EncryptedItem; answer: WriteAnswer; from: string; manifest: ManifestEntry | null } | null> {
  let retried = false;
  for (let sends = 1; ; sends++) {
    try {
      const v = vaultFor(vaultId);
      const move = vaultId !== base.vaultId;
      // A move encrypts afresh (the counter is `next.rev + 1`): never from below the counter the item has now.
      const moved = move ? { ...next, rev: Math.max(revOf(next), revOf(base.item)) } : next;
      const enc = (move ? v.key.encryptItem(moved, base.id, vaultId) : v.key.updateItem(base.enc, next)) as EncryptedItem;
      // The trash state the server keeps (an edit or a move never changes it).
      const after: ManifestRow = { id: base.id, deleted_at: synced?.items.get(base.id)?.deleted_at ?? base.deletedAt ?? null, data: enc.data };
      const left = move ? manifestFor(base.vaultId, vaultFor(base.vaultId).key, [base.id], []) : null;
      const manifest = manifestFor(vaultId, v.key, move ? [] : [base.id], [after]);
      await onBody?.({ key: enc.key, data: enc.data, key_epoch: v.epoch ?? null });
      const answer = await api<WriteAnswer>(`/items/${base.id}`, { method: "PUT", body: { ...enc, revision: base.revision, ...epochOf(v), ...manifestsOf(left, manifest) } });
      return { enc, answer, from: base.vaultId, manifest };
    } catch (e) {
      const raced = mustCatchUp(e);
      if (!keyChanged(e) && !revisionConflict(e) && !raced) throw e;
      if (raced && sends >= MANIFEST_TRIES) throw triesOver(e);
      await catchUp();
      const fresh = serverItems.find((x) => x.id === base.id);
      if (!fresh) throw new Error(ITEM_GONE);
      if (fresh.deletedAt === base.deletedAt && holds(fresh, next, vaultId)) return null;
      if (!sameItem(fresh, base)) throw new Error(CHANGED_ELSEWHERE);
      if (!raced) {
        if (retried) throw new Error(keyChanged(e) ? KEY_CHANGED_AGAIN : CHANGED_ELSEWHERE);
        retried = true;
      }
      base = fresh;
    }
  }
}

/**
 * Move an item to the trash, back out of it, or delete it for good (requests without a body). In a vault with a
 * manifest the request names the item's revision and carries the vault's next manifest in its query; when the item or
 * the vault changed meanwhile (409 `revision_conflict` / `manifestRaced`, nothing written) it syncs and is sent again,
 * at most `MANIFEST_TRIES` sends in all, unless the item is gone or already where it should be (null: nothing to do).
 * Vaults without a manifest get the request from before.
 */
async function changeItemState(
  id: string,
  kind: "trash" | "restore" | "purge",
  /** The offline sender: a 409 `revision_conflict` is thrown (it decides again itself) instead of tried again here. */
  once = false,
): Promise<{ vaultId: string | undefined; answer: WriteAnswer; manifest: ManifestEntry | null } | null> {
  const path = kind === "trash" ? `/items/${id}` : kind === "restore" ? `/items/${id}/restore` : `/items/${id}/permanent`;
  const method = kind === "restore" ? "POST" : "DELETE";
  requireWritableServer();
  for (let sends = 1; ; sends++) {
    const row = synced?.items.get(id);
    const vaultId = row?.vault_id ?? vaultOf(id);
    const v = state.vaults.find((x) => x.id === vaultId);
    let manifest: ManifestEntry | null = null;
    try {
      if (v && vaultId) {
        // Only null or not counts for the trash state; the server stamps the time.
        const after: ManifestRow[] = kind === "purge" ? [] : [{ id, deleted_at: kind === "trash" ? Math.max(1, Math.floor(Date.now() / 1000)) : null, data: row?.data }];
        manifest = manifestFor(vaultId, v.key, [id], after);
      }
      const params = manifest && row ? [`revision=${row.revision}`, ...manifestQuery(manifest)] : [];
      return { vaultId, manifest, answer: await api<WriteAnswer>(withQuery(path, params), { method }) };
    } catch (e) {
      if (!mustCatchUp(e) && !(manifest && revisionConflict(e) && !once)) throw e;
      if (sends >= MANIFEST_TRIES) throw triesOver(e);
      await catchUp();
      const fresh = synced?.items.get(id);
      if (!fresh) return null;
      if (kind !== "purge" && ((fresh.deleted_at ?? null) !== null) === (kind === "trash")) return null;
    }
  }
}

export async function trashItem(id: string) {
  if (!offlineOn()) return sendTrash(id);
  requireWritableServer();
  await flightOf(id);
  const waitAs = () => {
    const vaultId = changeFor(changes, id)?.vault_id ?? vaultOf(id);
    if (!vaultId) throw new Error(ITEM_GONE);
    return queueChange({ kind: "trash", vault_id: vaultId, item_id: id, base_revision: synced?.items.get(id)?.revision ?? null, item: null });
  };
  if (changeFor(changes, id) || knownOffline()) return waitAs();
  try {
    await sendTrash(id);
  } catch (e) {
    if (!waitsAfter(failureOf(e))) throw e;
    noteOffline();
    await waitAs();
  }
}

async function sendTrash(id: string, once = false) {
  const w = await changeItemState(id, "trash", once);
  // The server stamps when it went to the trash, so it is fetched rather than guessed.
  if (w) await settle(w.vaultId, w.answer, undefined, w.manifest);
}

/** Restore, delete for good and moves need a connection, and an item with a change waiting takes none of them. */
function requireNoChange(id: string) {
  if (!offlineOn()) return;
  if (changeFor(changes, id)) throw new Error(HAS_CHANGE);
  if (knownOffline()) throw new Error(NEEDS_CONNECTION);
}

export async function restoreItem(id: string) {
  requireNoChange(id);
  const w = await changeItemState(id, "restore");
  if (!w) return;
  const { vaultId, answer } = w;
  await settle(
    vaultId,
    answer,
    (vaultSeq) => {
      const before = synced?.items.get(id);
      if (!before || before.vault_id !== vaultId || typeof answer?.revision !== "number") return null;
      return { kind: "upsert", vaultSeq, row: { ...before, deleted_at: null, revision: answer.revision, updated_at: Math.floor(Date.now() / 1000) } };
    },
    w.manifest,
  );
}

export async function purgeItem(id: string) {
  requireNoChange(id);
  const w = await changeItemState(id, "purge");
  if (!w) return;
  const { vaultId, answer } = w;
  // Deleted for good by this device: its edit counter and any copy kept for it go, however the result is shown.
  ghosts.delete(id);
  if (account) {
    const revs = revMemoryFor(account);
    revs.forget([id]);
    revs.flush();
  }
  await settle(vaultId, answer, vaultId ? (vaultSeq) => ({ kind: "remove", id, vaultId, vaultSeq }) : undefined, w.manifest);
}

// --------------------------------------------------------- offline changes

/**
 * Offline changes (ARCHITECTURE "Offline changes"), desktop app only: the platform's `offlineChanges` store is the
 * capability, so the browser web vault (no store) writes as before. Rules are in `offline-changes.ts`; here they are
 * stored (sealed with the account key), shown on top of the copy (`withChanges`) and sent (`kickSender`).
 */
const offlineStore = () => getDesktop()?.offlineChanges ?? null;
const offlineOn = (): boolean => offlineStore() !== null;
/** Whether offline changes are kept on this platform (the desktop app). */
export const offlineChangesOn = offlineOn;

const knownOffline = (): boolean => offlineHint || (typeof navigator !== "undefined" && navigator.onLine === false);
function noteOffline() {
  offlineHint = true;
}

/** A failed request, described for the pure rules. */
function failureOf(e: unknown): Failure {
  if (e instanceof UnreachableError) return { unreachable: true, ...(e.status ? { status: e.status } : {}) };
  if (e instanceof ApiError) return { status: e.status, code: e.code };
  return {};
}

/** The items to show: the server's copy with this account's offline changes on top. */
function withChanges(items: VaultEntry[], vaults: readonly Vault[] = state.vaults): VaultEntry[] {
  if (!changes.changes.length) return items;
  return overlay(items, changes, new Set(vaults.map((v) => v.id)), (a, b) => byName.compare(a.item.name, b.item.name));
}

/** Show the list as it is now (items, markers, the sync status). */
function publishChanges() {
  retryWhileWaiting();
  if (state.status !== "unlocked" && state.status !== "two-step") return;
  set({ items: withChanges(serverItems), offlineChanges: changes.changes });
}

let storing: Promise<void> = Promise.resolve();

/** Keep `next` as the list (memory at once, then sealed in the store, writes in order) and show it. */
async function storeChanges(next: ChangeList): Promise<void> {
  const acct = account;
  if (changesUnreadable) throw new OfflineChangeError(LIST_UNREADABLE);
  const accountId = changesFor ?? bundle?.account_id ?? null;
  if (!acct || !accountId) throw new Error(LOCKED);
  const sealed = next.changes.length ? acct.sealOfflineChanges(serializeList(next)) : null;
  changes = next;
  changesFor = accountId;
  publishChanges();
  const store = offlineStore()!;
  const write = storing.catch(() => {}).then(() => store.set(accountId, sealed));
  storing = write;
  await write;
}

/** Put a change into the list (merged with the item's change, if it has one), then try to send it. */
async function queueChange(c: Omit<NewChange, "id" | "created_at">): Promise<void> {
  if (!account || state.status !== "unlocked") throw new Error(LOCKED);
  const next = mergeChange(changes, { ...c, id: core.newId(), created_at: Date.now() });
  await storeChanges(next);
  kickSender();
}

/** The change being sent right now, by item id (a new change to that item waits for it). */
const flights = new Map<string, Promise<unknown>>();
async function flightOf(itemId: string): Promise<void> {
  await flights.get(itemId)?.catch(() => {});
}

let sendRun: Promise<void> | null = null;
let sendAgain = false;
/** Inside the sender's own syncs: the checked syncs they make don't start another run or count for held changes. */
let senderSyncs = 0;
/** Checked syncs taken over since unlock (not counting the sender's own): held changes are tried again after a newer one. */
let checkedSyncs = 0;

function afterCheckedSync() {
  offlineHint = false;
  // The sender's own syncs (and the write paths' syncs inside a send) don't start another run.
  if (senderSyncs) return;
  checkedSyncs++;
  kickSender();
}

/**
 * Send the waiting changes: one run at a time per app (one account is unlocked), while unlocked, oldest first,
 * stopping at the first failure without an answer. A kick during a run makes one more run after it.
 */
export function kickSender() {
  if (!offlineOn() || !changes.changes.length || state.status !== "unlocked") return;
  if (sendRun) {
    sendAgain = true;
    return;
  }
  sendRun = (async () => {
    do {
      sendAgain = false;
      await sendWaiting();
    } while (sendAgain && state.status === "unlocked" && changes.changes.length);
  })()
    .catch(() => {})
    .finally(() => {
      sendRun = null;
    });
}

async function sendWaiting() {
  if (typeof navigator !== "undefined" && navigator.onLine === false) return;
  const gen = generation;
  for (const { id } of [...changes.changes]) {
    if (gen !== generation || state.status !== "unlocked") return;
    const c = changes.changes.find((x) => x.id === id);
    if (!c || c.state === "conflict") continue;
    if (c.state === "held" && (heldSeen.get(c.id) ?? -1) >= checkedSyncs) continue;
    senderSyncs++;
    const flight: Promise<"offline" | "next"> = sendOne(c.id, gen).finally(() => {
      senderSyncs--;
      if (flights.get(c.item_id) === flight) flights.delete(c.item_id);
    });
    flights.set(c.item_id, flight);
    if ((await flight) === "offline") {
      noteOffline();
      return;
    }
  }
}

/** The server's row for an item, as the last checked sync holds it. */
function serverRow(itemId: string): ServerRow | null {
  const r = synced?.items.get(itemId);
  return r ? { vault_id: r.vault_id, revision: r.revision, data: r.data, deleted_at: r.deleted_at ?? null } : null;
}

/** A sync made by the sender (inside a flight, so it counts as the sender's own, see `senderSyncs`). */
const senderSync = catchUp;

async function sendOne(changeId: string, gen: number): Promise<"offline" | "next"> {
  const current = () => (gen === generation ? changes.changes.find((x) => x.id === changeId) : undefined);
  const update = async (patch: Partial<OfflineChange>) => {
    const c = current();
    if (c) await storeChanges(replaceChange(changes, { ...c, ...patch }));
  };
  const hold = async (reason: string) => {
    heldSeen.set(changeId, checkedSyncs);
    await update({ state: "held", reason });
  };
  const conflict = (why: "changed" | "deleted" | "moved") =>
    update({ state: "conflict", reason: why === "deleted" ? DELETED_TEXT : why === "moved" ? MOVED_TEXT : CONFLICT_TEXT });
  const done = async () => {
    if (current()) await storeChanges(removeChange(changes, changeId));
  };
  const keepSent = async (body: SentBody) => update({ sent: body });
  let decisions = 0;
  let races = 0;
  let renamed = false;
  for (;;) {
    const c = current();
    if (!c) return "next";
    // Never into a vault this sync didn't check and open, one that has a warning, or one this account can't write.
    const v = state.vaults.find((x) => x.id === c.vault_id);
    // Refused by signed sharing or waiting for consent: a warning, not gone.
    const refused = state.blockedVaults.some((b) => b.id === c.vault_id) || state.consents.some((b) => b.id === c.vault_id);
    const warning = refused || (!!v && (!!v.manifestWarning || unchecked.has(v.id)));
    const held = holdReason(v || refused ? { writable: v ? v.role !== "read" : true, warning } : null);
    if (held) {
      await hold(held);
      return "next";
    }
    let row = serverRow(c.item_id);
    // In another vault now (moved on another device): changed elsewhere for an edit or trash.
    if (row && row.vault_id !== c.vault_id && c.kind !== "create") {
      await conflict("moved");
      return "next";
    }
    if (row && row.vault_id !== c.vault_id) row = { ...row, data: "" };
    const stored = row ? (serverItems.find((x) => x.id === c.item_id)?.item ?? null) : null;
    const step = decideSend(c, row, stored);
    try {
      switch (step.step) {
        case "done":
          await done();
          return "next";
        case "conflict":
          await conflict(step.why);
          return "next";
        case "new-id":
          // Once only: an id taken twice is held.
          if (renamed) {
            await hold(friendlyError(new ApiError(409, "item_exists", "item id already exists")));
            return "next";
          }
          renamed = true;
          await update({ item_id: core.newId(), sent: null });
          continue;
        case "post":
          requireWritableServer();
          await postItem(c.vault_id, c.item as Item, c.item_id, keepSent, false);
          break;
        case "put": {
          const base = serverItems.find((x) => x.id === c.item_id);
          if (!base || base.revision !== step.revision) throw new Error("This item can't be opened on this device, so your change can't be sent.");
          await saveOver(base, c.item as Item, c.vault_id, keepSent);
          break;
        }
        case "trash":
          await sendTrash(c.item_id, true);
          break;
      }
      // Sent. A change merged into it meanwhile can't be (a new change to an item waits for its flight).
      await done();
      return "next";
    } catch (e) {
      if (gen !== generation) return "next";
      const kind = classifyFailure(failureOf(e));
      if (kind === "offline") return "offline";
      if (kind === "revision" || kind === "exists" || (e instanceof Error && (e.message === CHANGED_ELSEWHERE || e.message === ITEM_GONE))) {
        // Sync and decide again (a create whose id exists: done if it holds what was sent, else a new id).
        if (++decisions >= MAX_TRIES && kind !== "exists") {
          await conflict(serverRow(c.item_id) ? "changed" : "deleted");
          return "next";
        }
        try {
          await senderSync();
        } catch (s) {
          if (classifyFailure(failureOf(s)) === "offline") return "offline";
          throw s;
        }
        continue;
      }
      if (kind === "retry") {
        if (++races >= MAX_TRIES) {
          await hold(friendlyError(e));
          return "next";
        }
        try {
          await senderSync();
        } catch {
          return "offline";
        }
        continue;
      }
      // Any other answer (or a vault that no longer checks out): held with the app's wording.
      await hold(friendlyError(e));
      return "next";
    }
  }
}

// When the connection comes back, sync (which sends what waits).
if (typeof window !== "undefined") {
  window.addEventListener("online", () => {
    offlineHint = false;
    if (offlineOn() && state.status === "unlocked" && changes.changes.length) void sync().catch(() => {});
  });
}

/** While changes wait for the connection (unlocked), a sync every minute, in case the connection came back without an `online` event. */
let retryTimer: ReturnType<typeof setInterval> | null = null;
function retryWhileWaiting() {
  // Only changes that wait for the connection: held ones are tried again after the next ordinary sync.
  const waiting = state.status === "unlocked" && changes.changes.some((c) => c.state === "waiting");
  if (!waiting) {
    if (retryTimer) clearInterval(retryTimer);
    retryTimer = null;
    return;
  }
  retryTimer ??= setInterval(() => {
    if (state.status !== "unlocked" || !changes.changes.some((c) => c.state === "waiting")) return retryWhileWaiting();
    if (typeof navigator !== "undefined" && navigator.onLine === false) return;
    void sync().catch(() => {});
  }, 60_000);
}

/** Discard this change: it is removed from the list (the item shows the server's copy again). */
export async function discardChange(itemId: string): Promise<void> {
  await flightOf(itemId);
  const c = changeFor(changes, itemId);
  if (c) await storeChanges(removeChange(changes, c.id));
}

/** What the decision sheet of an item's conflict shows: this device's version and the server's. */
export interface ConflictView {
  change: OfflineChange;
  kind: ConflictKind;
  /** The server's current version (null: deleted on another device). */
  other: VaultEntry | null;
  /** The item is in another vault now (moved on another device). */
  moved: boolean;
}

export function conflictView(itemId: string): ConflictView | null {
  const change = changeFor(changes, itemId);
  if (!change || change.state !== "conflict") return null;
  const row = serverRow(change.item_id);
  const kind = conflictKind(change, row);
  if (!kind) return null;
  const moved = !!row && row.vault_id !== change.vault_id;
  return { change, kind, moved, other: row ? (serverItems.find((x) => x.id === change.item_id) ?? null) : null };
}

/** The user's answer to a conflict; then the sender goes on (nothing is sent before they answer). */
export async function resolveChange(itemId: string, answer: Resolution): Promise<void> {
  const c = changeFor(changes, itemId);
  if (!c) return;
  const next = resolveConflict(changes, c.id, answer, serverRow(itemId), core.newId());
  heldSeen.delete(c.id);
  await storeChanges(next);
  kickSender();
}

/**
 * How many changes wait for the signed-in account, for the warning before they are deleted: a number while unlocked,
 * null while locked when a list is stored (it can't be read then), 0 when there is none or on other platforms.
 */
export async function pendingChangeCount(): Promise<number | null> {
  const store = offlineStore();
  if (!store) return 0;
  if (account && changesFor) return changes.changes.length;
  const accountId = bundle?.account_id;
  if (!accountId) return 0;
  try {
    return (await store.get(accountId)) ? null : 0;
  } catch {
    return 0;
  }
}

/** Delete the signed-in account's list (Log out, Change server, Delete account: after the warning). */
export async function deleteOfflineChanges(): Promise<void> {
  const store = offlineStore();
  const accountId = changesFor ?? bundle?.account_id;
  changes = emptyList();
  heldSeen = new Map();
  if (state.offlineChanges.length) publishChanges();
  if (!store || !accountId) return;
  await storing.catch(() => {});
  await store.set(accountId, null).catch(() => {});
  changesUnreadable = false;
  if (state.offlineNotice) set({ offlineNotice: null });
}

// ---------------------------------------------------------------- history

/** Earlier versions of an item, newest first (servers with `item_history`; any member of its vault may list them). */
export async function listItemVersions(itemId: string): Promise<ItemVersion[]> {
  return readVersions(await api(`/items/${itemId}/versions`));
}

/**
 * One earlier version, decrypted with its vault's key. A version is encrypted with the vault key of its time; replacing
 * the key deletes the vault's versions, so the current key opens every version the server still lists.
 */
export async function openItemVersion(itemId: string, seq: number): Promise<{ version: ItemVersion; item: Item }> {
  const stored = readVersion(await api(`/items/${itemId}/versions/${seq}`));
  if (!stored) throw new Error("The server sent an unexpected response. Try again.");
  // Looked up after the request: a sync meanwhile may have replaced the key handle.
  const v = vaultFor(stored.vaultId);
  let item: Item;
  try {
    item = v.key.decryptItem({ id: itemId, vault_id: stored.vaultId, key: stored.itemKey, data: stored.data }) as Item;
  } catch {
    throw new Error("This version can't be opened with the vault's current key.");
  }
  return { version: { seq: stored.seq, savedAt: stored.savedAt, savedBy: stored.savedBy }, item };
}

/**
 * Restore an earlier version: an ordinary edit with its content (key epoch, revision check, delta sync as any save), so
 * what the item holds now becomes a version in turn. Earlier passwords of both are kept in the password history.
 */
export async function restoreItemVersion(entry: VaultEntry, version: Item) {
  await updateItem(entry, restoredItem(version, entry.item));
}

const IMPORT_BATCH = 250;
/** Encrypted bytes per import request at most, well below the server's 64 MiB limit for a request body. */
const IMPORT_BATCH_BYTES = 16 * 1024 * 1024;
/** Tries per batch after network or server failures (a vault key change gets one more). */
const IMPORT_TRIES = 3;
const LOCKED_DURING_IMPORT = "The vault was locked during the import. Unlock it and import the file again.";

/** What the server takes per import (`/api/config` `limits`; older servers don't say). */
export interface ImportLimits {
  max_import_items?: number;
  max_item_kib?: number;
}

const positive = (n: unknown): number | undefined => (typeof n === "number" && Number.isFinite(n) && n >= 1 ? Math.floor(n) : undefined);

/**
 * An imported item as it is saved: the file's creation time when it has one, saved now. A file list is left out: its
 * files belong to the item they were attached to (removing one from the copy would delete the original's file).
 */
const forImport = (it: Item, now: number): Item => ({ ...stripAttachments(it), created_at: it.created_at || now, updated_at: now });

/**
 * Indexes of the items whose encrypted form is larger than the server takes (`max_item_kib`): they can't be imported.
 * Only items near the limit are measured exactly, by encrypting them.
 */
export function oversizedForImport(vaultId: string, items: Item[], maxItemKib: number): number[] {
  const limit = maxItemKib * 1024;
  const now = Math.floor(Date.now() / 1000);
  const out: number[] = [];
  items.forEach((it, i) => {
    const item = forImport(it, now);
    if (encryptedSizeBound(item) <= limit) return;
    try {
      const enc = vaultFor(vaultId).key.encryptItem(item, core.newId(), vaultId) as EncryptedItem;
      if (enc.data.length > limit || enc.key.length > limit) out.push(i);
    } catch {
      /* not encryptable at all: the import itself reports it */
    }
  });
  return out;
}

/**
 * Encrypt and upload imported items in batches: at most the server's `max_import_items` (and 250) items and 16 MiB
 * per request. After a network or server failure a batch is sent again with the same item ids and the same request,
 * so a batch that was saved but whose answer got lost isn't saved twice. Items too large for the server must be left
 * out first (`oversizedForImport`): a batch is saved whole or not at all.
 */
export async function importItems(vaultId: string, items: Item[], progress?: (done: number) => void, limits?: ImportLimits) {
  requireWritableServer();
  const gen = generation;
  const now = Math.floor(Date.now() / 1000);
  const perRequest = Math.min(IMPORT_BATCH, positive(limits?.max_import_items) ?? IMPORT_BATCH);
  let batch: { id: string; item: Item }[] = [];
  let bytes = 0;
  let done = 0;
  importing++;
  try {
    await sendBatches();
  } finally {
    importing--;
  }
  await sync();

  async function sendBatches() {
    for (const it of items) {
      const item = forImport(it, now);
      const size = encryptedSizeBound(item);
      if (batch.length && (batch.length >= perRequest || bytes + size > IMPORT_BATCH_BYTES)) await send();
      batch.push({ id: core.newId(), item });
      bytes += size;
    }
    if (batch.length) await send();
  }
  async function send() {
    if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
    await sendImportBatch(vaultId, batch, gen);
    done += batch.length;
    progress?.(done);
    batch = [];
    bytes = 0;
  }
}

/**
 * One import request. In a vault with a manifest it carries the vault's next manifest (every item of the batch added).
 * After it the next batch starts from that manifest when the answer says it is the vault's (`manifest_links`: the link
 * of the manifest sent, not just its version); otherwise
 * (a batch that turned out to be stored already, another device's write in between) a sync brings the vault's own.
 * When the vault changed before the request was stored (`manifestRaced`, nothing written) it syncs and sends the same
 * items with a new manifest, at most `MANIFEST_TRIES` such sends.
 */
async function sendImportBatch(vaultId: string, batch: { id: string; item: Item }[], gen: number) {
  // Look the key up for every encryption: a sync (the previous batch's, or after a key change) frees the old handle.
  const encrypt = () => {
    const v = vaultFor(vaultId);
    return batch.map((b) => ({ ...(v.key.encryptItem(b.item, b.id, vaultId) as EncryptedItem), ...epochOf(v) }));
  };
  const request = (items: ReturnType<typeof encrypt>) => {
    const manifest = manifestFor(vaultId, vaultFor(vaultId).key, [], items.map((i) => ({ id: i.id, deleted_at: null, data: i.data })));
    return { manifest, body: { items, ...manifestsOf(manifest) } };
  };
  let items = encrypt();
  let epoch = vaultFor(vaultId).epoch;
  let { manifest, body } = request(items);
  let rekeyed = false;
  let races = 0;
  for (let attempt = 1; ; attempt++) {
    try {
      const answer = await api<{ vault_seq?: unknown; manifest_seq?: unknown; manifest_seqs?: unknown; manifest_link?: unknown; manifest_links?: unknown } | null>("/items/import", { body });
      if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
      if (manifest) {
        const of = (all: unknown, one: unknown): unknown => (all && typeof all === "object" ? (all as Record<string, unknown>)[vaultId] : one);
        const stored = of(answer?.manifest_seqs, answer?.manifest_seq);
        const link = of(answer?.manifest_links, answer?.manifest_link);
        if (stored === manifest.seq && linkStored(manifest, link) && synced && typeof answer?.vault_seq === "number" && knownSeq(synced, vaultId) === answer.vault_seq - 1) {
          // The vault's manifest is this batch's: the next batch (or any other write) starts from it. The rows come
          // with the sync that ends the import.
          synced = applyOwnManifest(synced, vaultId, manifest, answer.vault_seq);
          rememberManifest(vaultId, manifest);
        } else await catchUp();
      }
      return;
    } catch (e) {
      if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
      if (mustCatchUp(e)) {
        if (++races >= MANIFEST_TRIES) throw triesOver(e);
        await catchUp();
        // The same ids; encrypted again only if the sync brought a new key (the request then names its epoch).
        if (vaultFor(vaultId).epoch !== epoch) {
          items = encrypt();
          epoch = vaultFor(vaultId).epoch;
        }
        ({ manifest, body } = request(items));
        attempt--;
      } else if (keyChanged(e) && !rekeyed) {
        rekeyed = true;
        await catchUp();
        items = encrypt(); // the same ids under the new key
        epoch = vaultFor(vaultId).epoch;
        ({ manifest, body } = request(items));
      } else if (attempt > 1 && itemExists(e)) {
        // A batch is saved whole or not at all, and its ids are new: an earlier try was saved, only its answer got lost.
        return;
      } else if (attempt < IMPORT_TRIES && transient(e)) {
        const seconds = e instanceof ApiError && e.retryAfter !== undefined ? Math.min(e.retryAfter, 60) : attempt * 2;
        await new Promise((resolve) => setTimeout(resolve, seconds * 1000));
        if (gen !== generation) throw new Error(LOCKED_DURING_IMPORT);
      } else throw keyChanged(e) ? new Error(KEY_CHANGED_AGAIN) : e;
    }
  }
}

// ------------------------------------------------------------------ vaults

export async function createVault(name: string): Promise<string> {
  if (!account) throw new Error("Vault is locked.");
  requireWritableServer();
  const id = core.newId();
  // Every vault starts at key epoch 0; bound to it (v2) when all the account's apps read that.
  const nv = accountWrapsV2 ? account.newVaultKeyBound(id, 0) : account.newVaultKey(id);
  const key = nv.takeKey();
  const meta = key.encryptMeta(id, { name });
  key.free();
  await api("/vaults", { body: { id, meta, wrapped_key: nv.wrapped } });
  await sync();
  vaultKeysChanged();
  return id;
}

export async function renameVault(id: string, name: string) {
  requireWritableServer();
  await withCurrentKey(() => {
    const v = vaultFor(id);
    return api(`/vaults/${id}`, { method: "PUT", body: { meta: v.key.encryptMeta(id, { name }), ...epochOf(v) } });
  });
  await sync();
}

export async function deleteVault(id: string) {
  await api(`/vaults/${id}`, { method: "DELETE" });
  // A tombstone, not forgetting: the vault served again is refused.
  if (signedSharingOn()) signed.markLeft(id);
  await sync();
  void signed.flushPins().catch(() => {});
}

/** Leave a vault shared with the account (an admin then replaces its key). */
export async function leaveVault(id: string) {
  await api(`/vaults/${id}/members/${state.userId}`, { method: "DELETE" });
  if (signedSharingOn()) signed.markLeft(id);
  await sync();
  void signed.flushPins().catch(() => {});
}

/** Someone found by `lookupUser`: their public identity (signing key and its signatures null for accounts without one yet). */
export interface FoundUser extends PublicIdentity {
  name: string;
}

/** Someone on this server to share a vault with, by email (404 when there is nobody); their keys checked to be strings. */
export async function lookupUser(email: string): Promise<FoundUser> {
  const answer = await api(`/users/lookup?email=${encodeURIComponent(email)}`);
  const found = readFoundUser(answer);
  const identity = readIdentity(answer);
  if (!found || !identity) throw new Error(UNEXPECTED_RESPONSE);
  return { ...identity, name: cleanText(found.name) };
}

/** A vault's members with its key epoch and member roster (`GET /vaults/{id}/members`). */
export async function loadMembers(vaultId: string): Promise<MembersAnswer> {
  const answer = readMembersAnswer(await api(`/vaults/${vaultId}/members`));
  if (!answer) throw new Error(UNEXPECTED_RESPONSE);
  return answer;
}

/** Whether this vault's changes are signed (the last sync ran signed sharing's checks). */
export const signsSharing = (): boolean => signedSharingOn();

/** Signed sharing: this account's identity fingerprint (from its own key); null before it has one or without the feature. */
export const identityFingerprint = (): string | null => signed.identityFingerprint();

/** How someone's identity compares with the account's known keys (for the members list and the share sheet). */
export const personState = signed.personState;

/**
 * "Mark as verified" (the identity shown is still the pinned one) or "Trust the new key" after their keys changed, for
 * exactly the identity shown (`shownHash`). Every vault is checked again.
 */
export async function trustPerson(identity: PublicIdentity, email: string, opts: { mode: "verify" | "trust"; shownHash: string }) {
  signed.trustPerson(identity, email, opts);
  await signed.flushPins().catch(() => {});
  await sync();
}

/** Errors of a signed change that a sync and one more try may fix: the roster, the members or the key moved meanwhile. */
const signedRaced = (e: unknown) => e instanceof RaceError || hasErrorCode(e, "member_roster_changed") || hasErrorCode(e, "vault_key_changed");

/** Names for user ids in messages: the pins first, then the rows the server listed. Never the raw id. */
const nameFrom =
  (rows: readonly { user_id: string; email: string; name: string }[]) =>
  (id: string): string | null =>
    signed.pinnedName(id) ?? namesFromRows(rows)(id);

/** A 409 `members_changed`: who differs, by name (from the pins, `rows`, then a fresh members list), or the general text. */
async function membersChangedError(e: unknown, vaultId: string, rows: readonly { user_id: string; email: string; name: string }[], what: string): Promise<Error> {
  const diff = e instanceof ApiError ? readMemberDiff(e.fields) : null;
  if (!diff) return e instanceof Error ? e : new Error(String(e));
  const fresh = await loadMembers(vaultId).catch(() => null);
  const differ = [...diff.unknown, ...diff.identity_changed, ...diff.role_changed];
  if (!differ.length) return new Error(`This vault's members changed just now. Check the members, then try again. PassAuth ${what}.`);
  return new Error(membersDifferText(differ, nameFrom([...rows, ...(fresh?.members ?? [])]), what));
}

/** Options of a signed change: `confirmed` once the user confirmed the member review (`ReviewNeededError`). */
export interface ChangeOptions {
  confirmed?: Confirmation;
}

/**
 * Share a vault (or change an existing member's or invitee's access). With servers that have invitations, someone who
 * isn't a member yet gets an invitation: "invited" until they accept. Null from older servers (always a member at once).
 * Signed sharing: throws `ReviewNeededError` when the user has to confirm the members first (the vault's first signed
 * list, or people who left); call again with `confirmed`.
 */
export async function shareVault(
  vaultId: string,
  user: { user_id: string; public_key: string; signing_key?: string | null; identity_signature?: string | null; x25519_signature?: string | null; email?: string },
  role: Role,
  opts: ChangeOptions = {},
): Promise<"invited" | "active" | null> {
  if (typeof user.user_id !== "string" || typeof user.public_key !== "string" || !user.public_key) throw new Error(UNEXPECTED_RESPONSE);
  requireWritableServer();
  const r = signedSharingOn()
    ? await signedShare(vaultId, { ...identityOf({ signing_key: null, identity_signature: null, x25519_signature: null, ...user }), email: cleanText(user.email) }, role, opts)
    : await withCurrentKey(() => {
        const v = vaultFor(vaultId);
        return api<{ status?: unknown; rotation_pending?: unknown } | null>(`/vaults/${vaultId}/members`, {
          body: { user_id: user.user_id, role, sealed_key: v.key.shareTo(vaultId, user.public_key), ...epochOf(v) },
        });
      });
  if (r?.rotation_pending === true) {
    // The vault was personal and wrapped for emergency contacts, who may hold its key: replace it now, for everyone
    // in it (the new invitee too). If that fails, the vault notices keep asking for it.
    try {
      await rotateVaultKey(vaultId);
    } catch (e) {
      throw new Error(`Shared, but the vault's key wasn't replaced yet: ${friendlyError(e)} Finish it with "Replace vault key" in this vault's settings.`);
    }
  }
  return r?.status === "invited" || r?.status === "active" ? r.status : null;
}

/** The member list a roster will list, from a members answer: identity, role and listed email. */
const rowsOf = (members: readonly SignedMemberRow[], change?: { user: PublicIdentity & { email: string }; role: Role }) => [
  ...members.filter((m) => m.user_id !== change?.user.user_id).map((m) => signed.memberInput(m)),
  ...(change ? [{ ...identityOf(change.user), role: change.role, email: change.user.email || null }] : []),
];

/**
 * Signed share (step 4): the recipient and the members reviewed against the vault's trusted roster and the known keys
 * (`planChange`), the recipient pinned, the key sealed and signed at the verified epoch, the members fetched again and
 * the next roster signed over them (the core refuses a list other than the reviewed one), sent together. When the
 * roster, members or key moved meanwhile, sync and try once more (a new review if the list changed).
 */
async function signedShare(vaultId: string, recipient: PublicIdentity & { email: string }, role: Role, opts: ChangeOptions) {
  for (let attempt = 1; ; attempt++) {
    try {
      const answer = await loadMembers(vaultId);
      const v = vaultFor(vaultId);
      if (v.epoch === undefined) throw new RaceError();
      const change = { user: recipient, role };
      const plan = signed.planChange({
        vaultId,
        answer,
        rows: rowsOf(answer.members, change),
        keyEpoch: v.epoch,
        target: recipient.user_id,
        confirmed: opts.confirmed,
        what: "didn't share the vault",
        nameOf: nameFrom(answer.members),
      });
      signed.pinReviewed(plan);
      const share = signed.sealAndSign(v.key, vaultId, recipient, role, v.epoch);
      // Fetched again right before signing: the roster must list exactly what was reviewed.
      const again = await loadMembers(vaultId);
      const now = vaultFor(vaultId);
      if (again.keyEpoch !== v.epoch || now.epoch !== v.epoch || again.rosterSeq !== answer.rosterSeq) throw new RaceError();
      const roster = signed.signRosterFor(now.key, vaultId, plan, v.epoch, rowsOf(again.members, change));
      let r: { status?: unknown; rotation_pending?: unknown } | null;
      try {
        r = await api<{ status?: unknown; rotation_pending?: unknown } | null>(`/vaults/${vaultId}/members`, {
          body: { user_id: recipient.user_id, role, sealed_key: share.sealed_key, signature: share.signature, roster, key_epoch: v.epoch },
        });
      } catch (e) {
        if (hasErrorCode(e, "members_changed")) throw await membersChangedError(e, vaultId, answer.members, "didn't share the vault");
        throw e;
      }
      signed.rememberSigned(vaultId, roster);
      void signed.flushPins().catch(() => {});
      return r;
    } catch (e) {
      if (!signedRaced(e) || attempt > 1) throw e instanceof RaceError ? new Error(KEY_CHANGED_AGAIN) : e;
      await catchUp();
    }
  }
}

/**
 * Accept a vault shared with the account: it becomes a membership, and the next sync brings the vault whole. Signed
 * sharing: only a signed invitation that passed every check can be accepted; its signer and key are pinned and its
 * roster remembered first.
 */
export async function acceptInvitation(vaultId: string, shown?: InvitationTrust) {
  const trust = state.invitations.find((i) => i.vaultId === vaultId)?.trust;
  if (signedSharingOn()) {
    if (trust?.kind !== "signed") throw new Error(trust?.kind === "refused" ? trust.reason : "This invitation isn't signed, so it can't be accepted. Decline it.");
    // Bound to what the dialog showed (review L-B): the signer, key id, epoch and roster must still be the same.
    if (!shown) throw new Error(signed.CHANGED_SINCE_SHOWN);
    signed.acceptInvitationTrust(vaultId, trust, shown);
  }
  try {
    await api(`/vaults/${vaultId}/invitation/accept`, { method: "POST" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
    // Cancelled by the person who shared it, or the vault is gone: show what is there now.
    await sync().catch(() => {});
    throw new Error("This invitation is no longer open. The person who shared the vault may have cancelled it.");
  } finally {
    void signed.flushPins().catch(() => {});
  }
  await sync();
}

/**
 * Decline a vault shared with the account. The server then asks the vault's owners and admins to replace its key: the
 * invitation already gave this account the key. Already gone (404) is fine: the list is refreshed. Signed sharing: a
 * signed invitation is declined only where its admission says `declinable` (else "Not now"), and once the server
 * answered (or 404) it is tombstoned with `pinsDecline` (round 5 M2: never a vault the account holds or one of this
 * sync's vault rows, never at a server-chosen roster version), so the same invitation served again is refused. An
 * unsigned or refused one is only declined on the server (nothing to remember: it can never be accepted).
 */
export async function declineInvitation(vaultId: string) {
  const trust = signedSharingOn() ? state.invitations.find((i) => i.vaultId === vaultId)?.trust : undefined;
  if (!signed.invitationDeclinable(trust)) throw new Error(DECLINE_NOT_OFFERED);
  try {
    await api(`/vaults/${vaultId}/invitation`, { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
  // Only after the server answered (review r5 I2): a failed decline leaves nothing behind.
  if (trust?.kind === "signed") {
    signed.markDeclined(vaultId);
    void signed.flushPins().catch(() => {});
  }
  await sync();
}

const DECLINE_NOT_OFFERED = "This vault can't be declined here. Leave it for now: it stays locked on this device until you accept it.";

/**
 * Accept a vault the server lists that the account never accepted (signed sharing; a signed one, or unsigned ones as
 * `Consent` allows), exactly as its dialog showed it (`shown`, captured when the dialog opened; review L-B).
 */
export async function acceptConsent(vaultId: string, shown: Consent) {
  const c = state.consents.find((x) => x.id === vaultId);
  if (!c) throw new Error("This vault is no longer waiting for you. Reload the page.");
  signed.acceptConsent(c.consent, shown);
  await signed.flushPins().catch(() => {});
  await sync();
}

/**
 * Decline a vault the server lists that the account never accepted, and leave the membership. Only where its admission
 * says `declinable` and it names its signer (rule 1: a server could make a real vault look like an unsigned one waiting
 * here; round 5 M2: never a re-join, replaced, own, first-signed or held one), and never a vault in use here. The pins
 * go through `pinsDecline`, which never tombstones one of this sync's vault rows.
 */
export async function declineConsent(vaultId: string) {
  const c = state.consents.find((x) => x.id === vaultId);
  if (!c) throw new Error("This vault is no longer waiting for you. Reload the page.");
  if (!signed.consentDeclinable(c.consent))
    throw new Error(c.consent.signer ? DECLINE_NOT_OFFERED : `This vault isn't signed, so it can't be declined here. ${ASK_OWNER_TO_SIGN}`);
  if (state.vaults.some((v) => v.id === vaultId)) throw new Error("This vault is in use now, so it wasn't declined. Reload the page.");
  signed.markDeclined(vaultId);
  await signed.flushPins().catch(() => {});
  await api(`/vaults/${vaultId}/members/${state.userId}`, { method: "DELETE" }).catch(() => {});
  await sync();
}

const rotationKey = (userId: string) => `pa.rotate.${userId}`;
function readPendingRotations(userId: string): string[] {
  try {
    const v = JSON.parse(read(rotationKey(userId)) ?? "[]");
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}
function setPendingRotation(vaultId: string, pending: boolean) {
  const list = readPendingRotations(state.userId).filter((id) => id !== vaultId);
  if (pending) list.push(vaultId);
  store(rotationKey(state.userId), list.length ? JSON.stringify(list) : null);
  set({ pendingRotations: list });
}

/** Options of a key replacement (signed sharing). */
export interface RotationOptions extends ChangeOptions {
  /** An automatic flow (emergency access): never creates a vault's first signed member list. */
  automatic?: boolean;
  /** The member set the caller checked (user ids): the replacement uses exactly that set, else it stops. */
  expectMembers?: readonly string[];
}

export { ReviewNeededError, type ReviewView, type Confirmation };

/**
 * Remove a member and rotate the vault key so they can't read future changes:
 * a fresh key is sealed to every remaining member and all items re-encrypted.
 * Signed sharing: throws `ReviewNeededError` when the user has to confirm the members first (the vault's first signed
 * list, or people who left); call again with `confirmed`.
 */
export async function removeMember(vaultId: string, userId: string, opts: RotationOptions = {}) {
  if (!account) throw new Error("Vault is locked.");
  // Rotation must re-encrypt every item, so check that all of them can be read before removing anyone.
  await sync();
  if (undecryptable.get(vaultId)) {
    if (!unopenableRows.get(vaultId)) throw new Error(`${NEWER_ITEMS_REKEY} Nobody was removed.`);
    throw new Error(
      "Some items in this vault can't be decrypted, so PassAuth can't replace the vault key after removing this person. Nobody was removed.",
    );
  }
  // Removal and the new key in one request, so nobody is ever removed without the key change.
  try {
    await sendRotation(vaultId, `/vaults/${vaultId}/members/${userId}/remove`, userId, opts);
  } catch (e) {
    // Servers before 0.6.4 don't have the combined request: remove, then replace the key.
    if (!(e instanceof ApiError) || (e.status !== 404 && e.status !== 405)) throw e;
    const r = await api<{ rotation_required?: boolean }>(`/vaults/${vaultId}/members/${userId}`, { method: "DELETE" });
    if (r?.rotation_required === false) return sync();
    setPendingRotation(vaultId, true);
    await rotateVaultKey(vaultId, opts);
    return;
  }
  setPendingRotation(vaultId, false);
  await sync();
  // Without its last other member the vault may be personal again.
  vaultKeysChanged();
}

/** Replace a vault's key and re-encrypt its items (finishes a member removal). */
export async function rotateVaultKey(vaultId: string, opts: RotationOptions = {}) {
  await sendRotation(vaultId, `/vaults/${vaultId}/rotate`, undefined, opts);
  setPendingRotation(vaultId, false);
  await sync();
  vaultKeysChanged();
}

/**
 * Replace the keys of these vaults, one after the other (after an emergency contact who may have kept their keys was
 * removed): automatic, so a vault whose member list isn't signed yet and has other members is left for the user.
 * `members`: the member set (user ids) the caller checked per vault; the replacement uses exactly that set. Vaults this
 * account no longer has or can't manage are skipped. The first failure stops it and is thrown; the server keeps asking
 * for the rest (`rotation_pending`).
 */
export async function rotateVaultKeys(vaultIds: readonly string[], members?: ReadonlyMap<string, readonly string[]>) {
  await sync();
  try {
    for (const id of vaultIds) {
      const v = state.vaults.find((x) => x.id === id);
      if (!v || (v.role !== "owner" && v.role !== "admin")) continue;
      await sendRotation(id, `/vaults/${id}/rotate`, undefined, { automatic: true, ...(members?.has(id) ? { expectMembers: members.get(id) } : {}) });
      setPendingRotation(id, false);
    }
  } finally {
    await sync().catch(() => {});
    vaultKeysChanged();
  }
}

/** Tries of a key replacement when an item changed or the roster moved while it was being sent (signed sharing). */
const ROTATION_TRIES = 3;
const LOCKED_DURING = "The vault was locked. Unlock it and try again.";
const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && new Set([...a, ...b]).size === a.length;

/**
 * Make a new vault key, seal it to every member except `without`, re-encrypt all
 * items and the vault name with it, and POST that to `path` (rotate, or remove + rotate).
 *
 * Signed sharing (step 5): only from the state this same sync verified (key, items, name, epoch), with the members
 * answer at that epoch and roster. The remaining members are reviewed against the trusted roster (`planChange`):
 * anyone it doesn't list or lists otherwise stops it, people who left and a vault's first signed list need the
 * user's confirmation; a vault without a roster whose only remaining member is this account is re-keyed for it alone
 * (nothing sealed, nothing signed). Every sealed key is signed at the new key epoch, the next roster lists exactly the
 * remaining members, and every item carries its revision, so an edit made meanwhile is never overwritten (409
 * `revision_conflict`: synced and sent again, as after the roster moved, at most `ROTATION_TRIES` times).
 */
async function sendRotation(vaultId: string, path: string, without?: string, opts: RotationOptions = {}) {
  if (!account) throw new Error("Vault is locked.");
  requireWritableServer();
  const gen = generation;
  const signing = signedSharingOn();
  const what = without ? "didn't remove anyone or change the key" : "didn't change the key";
  for (let attempt = 1; ; attempt++) {
    await sync();
    if (gen !== generation || !account) throw new Error(LOCKED_DURING);
    // A vault whose warning is unresolved takes no writes, a new key included.
    if (unresolved(manifestStatus.get(vaultId))) throw new Error(MANIFEST_HELD);
    // Nor one whose check this sync couldn't finish.
    if (unchecked.has(vaultId)) throw new Error(MANIFEST_UNCHECKED);
    if (undecryptable.get(vaultId)) {
      // Only rows from a newer app (nothing that doesn't decrypt): say what to do about them.
      if (!unopenableRows.get(vaultId)) throw new Error(NEWER_ITEMS_REKEY);
      throw new Error("Some items in this vault can't be decrypted, so its key can't be replaced yet.");
    }
    // Every member and invitee gets the new key: a row that can't be read stops the replacement (nobody is skipped).
    let answer: MembersAnswer;
    if (signing) answer = await loadMembers(vaultId);
    else {
      const all = readMembers(await api(`/vaults/${vaultId}/members`));
      if (!all) throw new Error(UNEXPECTED_RESPONSE);
      answer = {
        members: all.map((m) => ({ ...m, signing_key: null, identity_signature: null, x25519_signature: null, key_kind: null, share: null })),
        keyEpoch: undefined,
        roster: null,
        rosterSeq: 0,
      };
    }
    if (gen !== generation || !account) throw new Error(LOCKED_DURING);
    if (opts.expectMembers && !sameSet(answer.members.map((m) => m.user_id), opts.expectMembers))
      throw new Error("This vault's members changed just now, so PassAuth didn't replace its key automatically. Check the vault in Settings, Vaults & sharing.");
    const members = answer.members.filter((m) => m.user_id !== without);
    // The vault as this sync verified it: its key handle, epoch, items and name, looked up after the request.
    const v = state.vaults.find((x) => x.id === vaultId);
    if (signing && (v?.epoch === undefined || answer.keyEpoch !== v.epoch)) {
      // The key changed between the sync and the members list: sync again.
      if (attempt < ROTATION_TRIES) continue;
      throw new Error(KEY_CHANGED_AGAIN);
    }
    let plan: signed.ChangePlan | null = null;
    if (signing && v?.epoch !== undefined) {
      const trusted = signed.verifiedRoster(vaultId);
      if (trusted === undefined) throw new Error(signed.CHECK_LATER);
      const others = members.some((m) => m.user_id !== state.userId);
      if (trusted !== null || others) {
        try {
          plan = signed.planChange({
            vaultId,
            answer,
            rows: rowsOf(members),
            keyEpoch: v.epoch,
            ...(without ? { removed: without } : {}),
            automatic: !!opts.automatic,
            confirmed: opts.confirmed,
            what,
            nameOf: nameFrom(answer.members),
          });
        } catch (e) {
          if (e instanceof RaceError && attempt < ROTATION_TRIES) continue;
          throw e instanceof RaceError ? new Error(KEY_CHANGED_AGAIN) : e;
        }
        signed.pinReviewed(plan);
      }
      // No roster and nobody else: re-keyed for this account alone, nothing sealed or signed (the server accepts it
      // unsigned while the vault has no roster).
    }
    // The own wrap bound (v2) to the epoch the vault has after this write, when all the account's apps read that.
    const nv = accountWrapsV2 && v?.epoch !== undefined ? account.newVaultKeyBound(vaultId, v.epoch + 1) : account.newVaultKey(vaultId);
    const fresh = nv.takeKey();
    try {
      let keys: { user_id: string; wrapped_key: string; key_kind: string; signature?: string }[];
      let roster: string | undefined;
      if (plan && v?.epoch !== undefined) {
        ({ keys, roster } = signed.signedRotationKeys(fresh, nv.wrapped, vaultId, plan, v.epoch + 1));
      } else if (signing) {
        keys = members.filter((m) => m.user_id === state.userId).map((m) => ({ user_id: m.user_id, wrapped_key: nv.wrapped, key_kind: "account" }));
        if (keys.length !== members.length) throw new Error(KEY_CHANGED_AGAIN);
      } else {
        keys = members.map((m) =>
          m.user_id === state.userId
            ? { user_id: m.user_id, wrapped_key: nv.wrapped, key_kind: "account" }
            : { user_id: m.user_id, wrapped_key: fresh.shareTo(vaultId, m.public_key), key_kind: "sealed" },
        );
      }
      // Signed (also a vault re-keyed for this account alone, without a roster): each item with the revision it was
      // re-encrypted from (older servers ignore it).
      const items = serverItems
        .filter((e) => e.vaultId === vaultId)
        .map((e) => ({ ...(fresh.encryptItem(e.item, e.id, vaultId) as EncryptedItem), ...(signing ? { revision: e.revision } : {}) }));
      const meta = v ? fresh.encryptMeta(vaultId, { name: v.name }) : undefined;
      // Vault manifests: the new key makes new manifest keys, so a vault that has a manifest gets a whole new one, one
      // version up, sealed with the new key for the new epoch over every item as re-encrypted (its trash state kept),
      // and naming the manifest it replaces.
      const row = vaultRow(vaultId);
      let manifest: ManifestEntry | null = null;
      if (row && manifestSeq(row)) {
        const stored = serverItems.filter((e) => e.vaultId === vaultId);
        const held = [...(synced?.items.values() ?? [])].filter((r) => r.vault_id === vaultId).length;
        // Every item of the vault is re-encrypted (none hidden as undecryptable), at the epoch this sync verified.
        if (manifestStatus.get(vaultId) !== "ok" || v?.epoch === undefined || row.key_epoch !== v.epoch || held !== items.length) throw new Error(MANIFEST_HELD);
        const seq = manifestSeq(row) + 1;
        const rows = items.map((i, n) => ({ id: i.id, deleted_at: stored[n].deletedAt ?? null, data: i.data }));
        // It names the manifest it replaces by its link (sealed with the old key: the chain crosses keys by hashes alone).
        manifest = startEntry(fresh, vaultId, v.epoch + 1, seq, rowLink(row), rows);
      }
      let r: { key_epoch?: number } | null;
      try {
        // key_epoch: the epoch of the key being replaced, from the same sync as the items re-encrypted above.
        r = await api<{ key_epoch?: number } | null>(path, { body: { keys, items, meta, ...epochOf(v), ...(roster ? { roster } : {}), ...manifestsOf(manifest) } });
      } catch (e) {
        if (roster && hasErrorCode(e, "members_changed")) throw await membersChangedError(e, vaultId, answer.members, what);
        // The vault changed while this was being sent (another write, or its first manifest): nothing was changed.
        if (manifestRaced(e)) {
          if (attempt < ROTATION_TRIES) continue;
          throw new Error(MANIFEST_BUSY);
        }
        // An item was edited, or the roster moved, while this was being sent: nothing was changed, so sync and redo it.
        if (signing && attempt < ROTATION_TRIES && (revisionConflict(e) || hasErrorCode(e, "member_roster_changed"))) continue;
        if (hasErrorCode(e, "update_required")) throw new Error(MEMBERS_SIGNED_UPDATE);
        // 30 key replacements per vault and hour (signed sharing's retired key ids stay bounded).
        if (hasErrorCode(e, "rate_limited") || (e instanceof ApiError && e.status === 429)) throw new Error(KEY_REPLACEMENTS_LIMIT);
        if (!keyChanged(e)) throw e;
        // Someone else replaced the key after our sync, and nothing was changed. Show the vault as it is now and let
        // the user decide again. Their new key also finishes a removal this browser still had to secure.
        if (!without) setPendingRotation(vaultId, false);
        await sync().catch(() => {});
        throw new Error(
          without
            ? "Someone else replaced this vault's key just now, so nobody was removed. Check the members, then try again."
            : "Someone else replaced this vault's key just now. If the vault still asks for a new key, replace it again.",
        );
      }
      if (roster) signed.rememberSigned(vaultId, roster);
      // The new key is this device's own: pinned with the roster it signed (persisted unsent first, written below).
      if (signing && v?.epoch !== undefined) signed.recordOwnKey(vaultId, "account", fresh.epochPin(vaultId, v.epoch + 1), roster ?? null);
      // Servers from before the vault name moved into the rotation request (they report no key epoch) need it separately.
      if (meta && !without && typeof r?.key_epoch !== "number") await api(`/vaults/${vaultId}`, { method: "PUT", body: { meta } });
      if (signing) void signed.flushPins().catch(() => {});
      return;
    } finally {
      fresh.free();
    }
  }
}

/**
 * Sign a vault from before signed sharing (step 6; owners and admins): the member review always comes first (throws
 * `ReviewNeededError`; call again with `confirmed`), then every sealed member's key is sealed again and signed, and
 * the next member roster, in one request.
 */
export async function resignVault(vaultId: string, opts: ChangeOptions = {}) {
  if (!signedSharingOn()) throw new Error("Your server doesn't sign shared vaults yet.");
  for (let attempt = 1; ; attempt++) {
    try {
      const answer = await loadMembers(vaultId);
      const v = vaultFor(vaultId);
      if (v.epoch === undefined) throw new RaceError();
      const plan = signed.planChange({
        vaultId,
        answer,
        rows: rowsOf(answer.members),
        keyEpoch: v.epoch,
        always: true,
        confirmed: opts.confirmed,
        what: "didn't sign the vault",
        nameOf: nameFrom(answer.members),
      });
      signed.pinReviewed(plan);
      const body = signed.resignBody(v.key, vaultId, answer.members, plan, v.epoch);
      try {
        await api(`/vaults/${vaultId}/resign`, { body });
      } catch (e) {
        if (hasErrorCode(e, "members_changed")) throw await membersChangedError(e, vaultId, answer.members, "didn't sign the vault");
        throw e;
      }
      signed.rememberSigned(vaultId, body.roster);
      // Re-signed at the current key: this device doesn't then see its own signature as `first_signed`.
      signed.recordOwnKey(vaultId, v.kind, v.key.epochPin(vaultId, v.epoch), body.roster);
      void signed.flushPins().catch(() => {});
      await sync();
      return;
    } catch (e) {
      if (!signedRaced(e) || attempt > 1) throw e instanceof RaceError ? new Error(KEY_CHANGED_AGAIN) : e;
      await catchUp();
    }
  }
}

// ---------------------------------------------------- password / Secret Key

/**
 * Change master password and/or Secret Key setting. Returns the new Secret Key, if any. The new keys follow the server's
 * key-derivation minimums, so a change with the same password fixes a `kdf` policy violation.
 */
export async function changeKeys(currentPassword: string, newPassword: string, withSecretKey: boolean): Promise<string | null> {
  if (!account || !bundle) throw new Error("Vault is locked.");
  const reauthToken = await reauth(currentPassword);
  const kdf = await kdfMinimums();
  // Looked up again after the requests: a lock meanwhile frees the keys.
  if (!account || !bundle) throw new Error("Vault is locked.");
  const existing = bundle.secret_key_enabled ? rememberedSecretKey(state.email) : null;
  const next = account.rewrapWithKdf(bundle, newPassword, withSecretKey, existing ?? undefined, kdf.memory, kdf.iterations);
  const master = next.takeMaster();
  try {
    const start = core.opaqueRegisterStart(master);
    const resp = expectStrings(await api("/account/keys/start", { body: { message: start.message } }), "message");
    const upload = core.opaqueRegisterFinish(start.state, master, resp.message);
    await api("/account/keys/finish", { body: { upload, bundle: next.bundle }, headers: { "x-reauth-token": reauthToken } });
    bundle = next.bundle as Bundle;
    if (!withSecretKey) rememberSecretKey(state.email, null);
    else if (next.secretKey) rememberSecretKey(state.email, next.secretKey);
    // New keys may meet policies the old ones didn't (Secret Key, key derivation).
    void refreshPolicyViolations().catch(() => {});
    return next.secretKey ?? null;
  } finally {
    master.free();
    next.takeAccount().free();
    next.free();
  }
}

export { UnreachableError };
export const generatePassword = core.generatePassword;
export const generatePassphrase = core.generatePassphrase;
export const estimateBits = core.estimateBits;
export const totpCode = core.totpCode;
export const importFile = core.importFile;
export const exportVaultJson = core.exportVaultJson;
export const exportVaultEncrypted = core.exportVaultEncrypted;
export const exportVaultCsv = core.exportVaultCsv;
export const fingerprint = core.fingerprint;
