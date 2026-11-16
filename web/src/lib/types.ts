/** Mirrors `passauth_core::item` (snake_case JSON). */

export type UrlMatch = "default" | "domain" | "host" | "starts_with" | "exact" | "regex" | "never";
export type FieldType = "text" | "hidden" | "boolean";

export interface LoginUrl {
  url: string;
  match: UrlMatch;
}

export interface Passkey {
  credential_id: string;
  rp_id: string;
  rp_name: string;
  user_handle: string;
  user_name: string;
  user_display_name: string;
  algorithm: number;
  private_key: string;
  counter: number;
  discoverable: boolean;
  created_at: number;
}

export interface Login {
  username: string;
  password: string;
  urls: LoginUrl[];
  totp: string | null;
  passkeys: Passkey[];
}

export interface Card {
  cardholder_name: string;
  brand: string;
  number: string;
  exp_month: string;
  exp_year: string;
  code: string;
}

export interface Identity {
  title: string;
  first_name: string;
  middle_name: string;
  last_name: string;
  company: string;
  email: string;
  phone: string;
  address1: string;
  address2: string;
  city: string;
  state: string;
  postal_code: string;
  country: string;
  username: string;
  ssn: string;
  passport_number: string;
  license_number: string;
}

export interface SshKey {
  private_key: string;
  public_key: string;
  fingerprint: string;
}

export interface Field {
  name: string;
  value: string;
  type: FieldType;
}

/**
 * A file attached to an item (servers with `attachments`), listed inside the encrypted item. The core keeps the list
 * as an unknown field, so apps that don't know attachments save it back unchanged. `size` is the file's own size in
 * bytes (the server only knows the encrypted size); `key` is the file's own key (base64url), which opens nothing else.
 */
export interface Attachment {
  id: string;
  name: string;
  size: number;
  key: string;
}

export interface Item {
  /** Data format, set by the core on encrypt (older items are upgraded on decrypt). */
  format?: number;
  name: string;
  notes: string;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  login: Login | null;
  card: Card | null;
  identity: Identity | null;
  ssh_key: SshKey | null;
  fields: Field[];
  password_history: { password: string; changed_at: number }[];
  created_at: number;
  updated_at: number;
  /** Files attached to the item (absent when there are none); read them with `readAttachments` in attachments.ts. */
  attachments?: Attachment[];
}

export type ItemKind = "login" | "note" | "card" | "identity" | "ssh_key";

export function kindOf(i: Item): ItemKind {
  if (i.login) return "login";
  if (i.card) return "card";
  if (i.identity) return "identity";
  if (i.ssh_key) return "ssh_key";
  return "note";
}

export const KIND_LABEL: Record<ItemKind, string> = {
  login: "Login",
  note: "Secure note",
  card: "Card",
  identity: "Identity",
  ssh_key: "SSH key",
};

export function emptyItem(kind: ItemKind): Item {
  const now = Math.floor(Date.now() / 1000);
  return {
    name: "",
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: kind === "login" ? { username: "", password: "", urls: [{ url: "", match: "default" }], totp: null, passkeys: [] } : null,
    card: kind === "card" ? { cardholder_name: "", brand: "", number: "", exp_month: "", exp_year: "", code: "" } : null,
    identity:
      kind === "identity"
        ? { title: "", first_name: "", middle_name: "", last_name: "", company: "", email: "", phone: "", address1: "", address2: "", city: "", state: "", postal_code: "", country: "", username: "", ssn: "", passport_number: "", license_number: "" }
        : null,
    ssh_key: kind === "ssh_key" ? { private_key: "", public_key: "", fingerprint: "" } : null,
    fields: [],
    password_history: [],
    created_at: now,
    updated_at: now,
  };
}

export interface EncryptedItem {
  id: string;
  vault_id: string;
  key: string;
  data: string;
}

export interface VaultEntry {
  id: string;
  item: Item;
  vaultId: string;
  revision: number;
  deletedAt: number | null;
  enc: EncryptedItem;
}

export type Role = "owner" | "admin" | "write" | "read";
export type KeyKind = "account" | "sealed";

// ------------------------------------------------------------ API shapes

/** Encrypted account bundle (opaque to the UI except for these fields). */
export interface Bundle {
  account_id: string;
  kdf: unknown;
  secret_key_enabled: boolean;
  [k: string]: unknown;
}

export interface SyncVaultRow {
  id: string;
  meta: string;
  role: Role;
  wrapped_key: string;
  key_kind: KeyKind;
  /** 1 when someone who knew the key left: an admin must replace it (older servers omit it). */
  rotation_pending?: number;
  /**
   * Goes up by 1 with every replacement of the vault key (older servers omit it). Writes encrypted with this
   * vault's key carry it as `key_epoch`; a server with a newer key refuses them with 409 `vault_key_changed`.
   */
  key_epoch?: number;
  /** Delta sync: goes up with every write into the vault (servers without the `delta_sync` feature omit it). */
  seq?: number;
  /** Signed sharing (`signed_sharing`): the latest signed member roster's text (null: none) and its version (0: none). */
  member_roster?: string | null;
  member_roster_seq?: number;
  /** Signed sharing: the share signature of a sealed key and its signer, or null (unsigned); read with `readShare`. */
  share?: unknown;
}

export interface SyncItemRow {
  id: string;
  vault_id: string;
  item_key: string;
  data: string;
  revision: number;
  deleted_at: number | null;
  created_at: number;
  updated_at: number;
}

/**
 * A vault shared with the account and not accepted yet (servers with `vault_invitations`). Nothing of the vault reaches
 * the account until it accepts; `invitations.ts` reads these (malformed entries are left out).
 */
export interface SyncInvitation {
  vault_id: string;
  role: Role;
  /** The vault key sealed to this account's public key: opened only to read the vault's name. */
  wrapped_key: string;
  /** The vault's name, encrypted with that key. */
  meta: string;
  /** Who shared it, with their public key for the fingerprint; null once their account is deleted. */
  invited_by: { id: string; email: string; name: string; public_key: string } | null;
  invited_at: number | null;
  /** Signed sharing: the vault's key epoch (signed into the share), the share signature (`readShare`) and the latest roster. */
  key_epoch?: number;
  share?: unknown;
  member_roster?: string | null;
}

export interface SyncResponse {
  revision: number;
  /** `identity` and `key_pins_seq`: signed sharing (servers with `signed_sharing`), read by `signed-sharing.ts`. */
  user: { id: string; email: string; name: string; email_verified: boolean; identity?: unknown; key_pins_seq?: unknown };
  bundle: Bundle;
  vaults: SyncVaultRow[];
  items: SyncItemRow[];
  /** Pending invitations, always the full list (full and delta answers); servers without `vault_invitations` omit it. */
  invitations?: SyncInvitation[];
  /** Delta sync: opaque, sent back unchanged as `GET /sync?since=` (servers without `delta_sync` omit it). */
  cursor?: string;
  /** Delta answers only: items deleted for good or moved out of a vault since the cursor. Applied before `items`. */
  deleted?: { id: string; vault_id: string }[];
  /** Delta answers only: vaults sent whole (all their items are in `items`). */
  reset?: string[];
  /** True only on a delta answer; anything else is the whole account. */
  delta?: boolean;
}

export interface PreloginResponse {
  account_id: string;
  kdf: unknown;
  secret_key_required: boolean;
}

export interface LoginFinishResponse {
  user_id: string;
  email: string;
  access_token: string;
  refresh_token: string;
  bundle: Bundle;
  remember_token?: string;
  two_factor_required?: boolean;
  two_factor_token?: string;
  providers?: string[];
  reauth_token?: string;
}

export interface MemberRow {
  user_id: string;
  email: string;
  name: string;
  role: Role;
  public_key: string;
  /** "invited" until they accept (servers with `vault_invitations`; older servers omit it: everyone is a member). */
  status?: "active" | "invited";
  /** Who shared the vault with them and when (null for members from before invitations). */
  invited_by?: string | null;
  invited_at?: number | null;
}

// --------------------------------------------------------- runtime checks
//
// Every value from the server that reaches the core (or is rendered as text) is checked here first: the core's string
// parameters must get strings (anything else traps, or makes WASM memory grow for good), and React can't render an
// object. A malformed answer is an "unexpected response" error, never a crash.

/** The error text for an answer whose fields aren't what the app expects. */
export const UNEXPECTED_RESPONSE = "The server sent an unexpected response. Try again.";

const isStr = (v: unknown): v is string => typeof v === "string";
const filled = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const optNumber = (v: unknown) => v === undefined || (typeof v === "number" && Number.isFinite(v));
const optString = (v: unknown) => v === undefined || v === null || typeof v === "string";

/** An account bundle the core can be given: an object with the account's id. */
export const isBundle = (v: unknown): v is Bundle => isRecord(v) && filled(v.account_id);

/** The `/sync` answer's `user`: every field the app shows or keeps has its type. */
export const isSyncUser = (v: unknown): v is SyncResponse["user"] =>
  isRecord(v) && filled(v.id) && isStr(v.email) && isStr(v.name) && typeof v.email_verified === "boolean";

/** A `/sync` vault row: the fields that go to the core (`wrapped_key`, `key_kind`, `meta`) are strings, the numbers numbers. */
export const isSyncVaultRow = (v: unknown): v is SyncVaultRow =>
  isRecord(v) &&
  filled(v.id) &&
  isStr(v.meta) &&
  isStr(v.role) &&
  isStr(v.wrapped_key) &&
  isStr(v.key_kind) &&
  optNumber(v.rotation_pending) &&
  optNumber(v.key_epoch) &&
  optNumber(v.seq) &&
  optString(v.member_roster) &&
  optNumber(v.member_roster_seq);

/**
 * Runtime check of the /sync shape, so a server/client mismatch fails loudly instead of half-loading: the revision,
 * the user (id, email, name, email_verified), the bundle and the two lists. The rows are checked when the answer is
 * merged (`mergeSync` in delta.ts), so a malformed delta can be replaced by a full sync.
 */
export function isSyncResponse(v: unknown): v is SyncResponse {
  return isRecord(v) && typeof v.revision === "number" && isSyncUser(v.user) && isBundle(v.bundle) && Array.isArray(v.vaults) && Array.isArray(v.items);
}

/** `value`'s fields `keys` when each is a non-empty string; null otherwise. */
export function readStrings<K extends string>(value: unknown, ...keys: K[]): Record<K, string> | null {
  if (!isRecord(value)) return null;
  const out = {} as Record<K, string>;
  for (const k of keys) {
    const v = value[k];
    if (!filled(v)) return null;
    out[k] = v;
  }
  return out;
}

/** As `readStrings`, throwing `UNEXPECTED_RESPONSE` instead of returning null. */
export function expectStrings<K extends string>(value: unknown, ...keys: K[]): Record<K, string> {
  const out = readStrings(value, ...keys);
  if (!out) throw new Error(UNEXPECTED_RESPONSE);
  return out;
}

/** A `POST /auth/prelogin` answer; null when its account id, key derivation or Secret Key flag isn't usable. */
export function readPrelogin(value: unknown): PreloginResponse | null {
  if (!isRecord(value) || !filled(value.account_id) || !isRecord(value.kdf) || typeof value.secret_key_required !== "boolean") return null;
  return { account_id: value.account_id, kdf: value.kdf, secret_key_required: value.secret_key_required };
}

/**
 * A sign-in's answer (`/auth/login/finish`, the two-step answers): a two-step step (`two_factor_token`, `providers`), a
 * reauth token (`purpose: "reauth"`), or a session with its user, email, tokens and bundle. Null when it is none of them.
 * Other fields are kept (an approved device sign-in carries `sealed_key`).
 */
export function readLoginFinish(value: unknown): LoginFinishResponse | null {
  if (!isRecord(value) || !optString(value.remember_token) || !optString(value.reauth_token)) return null;
  const answer = value as unknown as LoginFinishResponse;
  if (value.two_factor_required === true) {
    if (!filled(value.two_factor_token)) return null;
    return { ...answer, two_factor_token: value.two_factor_token, providers: Array.isArray(value.providers) ? value.providers.filter(isStr) : [] };
  }
  if (filled(value.reauth_token) && value.access_token === undefined) return answer;
  const session = filled(value.user_id) && filled(value.email) && filled(value.access_token) && filled(value.refresh_token) && isBundle(value.bundle);
  return session ? answer : null;
}

/**
 * A vault's members (`GET /vaults/{id}/members`): every row needs its user id, email, name, role and public key as
 * strings. Null when any row doesn't (a key replacement must never skip a member, nor seal to garbage).
 */
export function readMembers(value: unknown): MemberRow[] | null {
  const list = isRecord(value) ? value.members : null;
  if (!Array.isArray(list)) return null;
  const out: MemberRow[] = [];
  for (const m of list) {
    if (!isRecord(m) || !filled(m.user_id) || !isStr(m.email) || !isStr(m.name) || !filled(m.role) || !filled(m.public_key)) return null;
    out.push({
      user_id: m.user_id,
      email: m.email,
      name: m.name,
      role: m.role as Role,
      public_key: m.public_key,
      ...(m.status === "active" || m.status === "invited" ? { status: m.status } : {}),
      ...(isStr(m.invited_by) || m.invited_by === null ? { invited_by: m.invited_by } : {}),
      ...(typeof m.invited_at === "number" && Number.isFinite(m.invited_at) ? { invited_at: m.invited_at } : {}),
    });
  }
  return out;
}

/** The `recovery_codes` of a two-step answer (shown once): the codes when they are strings, else null (none made). */
export function readRecoveryCodes(value: unknown): string[] | null {
  const codes = isRecord(value) ? value.recovery_codes : null;
  if (!Array.isArray(codes)) return null;
  const out = codes.filter(filled);
  return out.length ? out : null;
}

/** `GET /users/lookup`: someone to share with; null without a user id or public key. */
export function readFoundUser(value: unknown): { user_id: string; name: string; public_key: string } | null {
  if (!isRecord(value) || !filled(value.user_id) || !filled(value.public_key)) return null;
  return { user_id: value.user_id, name: isStr(value.name) ? value.name : "", public_key: value.public_key };
}

/** Safe href for a stored website: only http(s) links are clickable. */
export function safeHref(url: string): string | null {
  const t = url.trim();
  const full = t.includes("://") ? t : `https://${t}`;
  if (!/^https?:\/\//i.test(full)) return null;
  try {
    const u = new URL(full);
    return /^https?:$/.test(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}

/** Host of the first website (patterns excluded), for site icons. */
export function siteHost(item: Item): string {
  for (const u of item.login?.urls ?? []) {
    if (u.match === "regex" || !u.url) continue;
    try {
      const href = safeHref(u.url);
      if (!href) continue;
      const p = new URL(href);
      if (/^https?:$/.test(p.protocol)) return p.hostname;
    } catch {
      /* not a URL */
    }
  }
  return "";
}
