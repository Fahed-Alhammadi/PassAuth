/**
 * Duplicate logins (ARCHITECTURE "Duplicate logins"): logins of one account saved more than once, found on this device
 * after unlock, and how two or more of them are combined into one. The server never learns which logins look alike.
 *
 * Pure and unit-tested (`duplicates.test.ts`): no React and no network. Callers pass in the core's `baseDomain` (the
 * full Public Suffix List, WASM) and, for `combineGroup`, the vault's own write functions.
 *
 * A group: 2 or more logins in the same vault that can be written to (and passed its checks, with no waiting offline
 * change on any of them), not in the trash, with a password, where every pair has the same password (exact), the same
 * user name (trimmed, case-insensitive) and at least one http(s) website each with the same registrable domain.
 */
import type { Field, Item, LoginUrl, Passkey } from "./types";

/** What grouping reads from a vault entry (a `VaultEntry` fits). */
export interface DuplicateEntry {
  id: string;
  vaultId: string;
  revision: number;
  deletedAt: number | null;
  item: Item;
  /** The server sent an older version than this device saw: not checked, so never combined. */
  rollback?: boolean;
}

export interface DuplicateOptions {
  /** The core's `baseDomain`: the registrable domain of a host ("signin.apple.com" → "apple.com"), else the host. */
  baseDomain: (host: string) => string;
  /** Whether a vault takes this write: the user can edit it and it passed its checks. */
  writableVault: (vaultId: string) => boolean;
  /** Items with an offline change waiting: never grouped. */
  pending?: ReadonlySet<string>;
}

/** One 2FA secret the combined login can keep. */
export interface TotpChoice {
  /** The secret as saved in the first login that has it (keeper first). */
  secret: string;
  /** Issuer and account from an otpauth:// address, else the name of the login it comes from. */
  label: string;
  /** Ids of the logins that carry it. */
  from: string[];
}

export interface DuplicateGroup<T extends DuplicateEntry = DuplicateEntry> {
  vaultId: string;
  /** The registrable domain the logins share (shown on the row). */
  site: string;
  /** The keeper's user name as saved. */
  username: string;
  /** The keeper: the login with attachments, otherwise the oldest. Its id, folder and created date stay. */
  keeper: T;
  /** Every login of the group, the keeper first, the others oldest first. */
  entries: T[];
  /** The distinct 2FA secrets of the group (keeper's first); empty when none has one. */
  totps: TotpChoice[];
  /** More than one distinct 2FA secret: the user picks the one to keep. */
  differentTotp: boolean;
}

/** Password history entries the combined login keeps, newest first (the editor keeps the same number). */
export const HISTORY_CAP = 20;

const hasAttachments = (i: Item): boolean => (i.attachments?.length ?? 0) > 0;
const userKey = (i: Item): string => (i.login?.username ?? "").trim().toLowerCase();
const created = (e: DuplicateEntry): number => (typeof e.item.created_at === "number" ? e.item.created_at : 0);
const oldestFirst = (a: DuplicateEntry, b: DuplicateEntry): number => created(a) - created(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/**
 * The registrable domains of a login's http(s) websites. A saved address without a scheme is https (as in matching);
 * other schemes (app addresses) and regular expressions are no website here.
 */
export function siteDomains(item: Item, baseDomain: (host: string) => string): Set<string> {
  const out = new Set<string>();
  for (const u of item.login?.urls ?? []) {
    if (typeof u?.url !== "string" || u.match === "regex") continue;
    const raw = u.url.trim();
    if (!raw) continue;
    let url: URL;
    try {
      url = new URL(raw.includes("://") ? raw : `https://${raw}`);
    } catch {
      continue;
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") continue;
    if (!url.hostname) continue;
    const domain = baseDomain(url.hostname);
    if (domain) out.add(domain);
  }
  return out;
}

const shares = (a: Set<string>, b: Set<string>): boolean => {
  for (const d of a) if (b.has(d)) return true;
  return false;
};

/**
 * The groups of duplicate logins among `entries`, largest first. Within one vault, password and user name, logins are
 * taken oldest first and each joins the first group whose every member shares a site with it (so every pair of a group
 * shares one), else starts its own. Groups where more than one login has attachments are left out.
 */
export function findDuplicates<T extends DuplicateEntry>(entries: readonly T[], opts: DuplicateOptions): DuplicateGroup<T>[] {
  const buckets = new Map<string, { entry: T; domains: Set<string> }[]>();
  for (const e of entries) {
    const login = e.item?.login;
    if (!login || e.deletedAt !== null || !login.password || e.rollback) continue;
    if (opts.pending?.has(e.id) || !opts.writableVault(e.vaultId)) continue;
    const domains = siteDomains(e.item, opts.baseDomain);
    if (domains.size === 0) continue;
    // NUL can't be typed into these fields, so the parts can't run into each other.
    const key = `${e.vaultId}\u0000${userKey(e.item)}\u0000${login.password}`;
    const list = buckets.get(key);
    if (list) list.push({ entry: e, domains });
    else buckets.set(key, [{ entry: e, domains }]);
  }
  const groups: DuplicateGroup<T>[] = [];
  for (const list of buckets.values()) {
    if (list.length < 2) continue;
    list.sort((a, b) => oldestFirst(a.entry, b.entry));
    const formed: (typeof list)[] = [];
    for (const one of list) {
      const home = formed.find((g) => g.every((m) => shares(m.domains, one.domains)));
      if (home) home.push(one);
      else formed.push([one]);
    }
    for (const members of formed) {
      if (members.length < 2) continue;
      if (members.filter((m) => hasAttachments(m.entry.item)).length > 1) continue;
      groups.push(makeGroup(members));
    }
  }
  return groups.sort((a, b) => b.entries.length - a.entries.length || a.site.localeCompare(b.site) || a.username.localeCompare(b.username));
}

function makeGroup<T extends DuplicateEntry>(members: { entry: T; domains: Set<string> }[]): DuplicateGroup<T> {
  // Members come oldest first: the keeper is the one with attachments, else the first.
  const keeperAt = Math.max(
    0,
    members.findIndex((m) => hasAttachments(m.entry.item)),
  );
  const ordered = [members[keeperAt], ...members.filter((_, i) => i !== keeperAt)];
  const keeper = ordered[0].entry;
  // The site shown: one every login has, else one the keeper shares with the next login.
  const common = [...ordered[0].domains].filter((d) => ordered.every((m) => m.domains.has(d))).sort();
  const site = common[0] ?? [...ordered[0].domains].filter((d) => ordered[1].domains.has(d)).sort()[0] ?? "";
  const totps = totpChoices(ordered.map((m) => m.entry));
  return {
    vaultId: keeper.vaultId,
    site,
    username: keeper.item.login?.username ?? "",
    keeper,
    entries: ordered.map((m) => m.entry),
    totps,
    differentTotp: totps.length > 1,
  };
}

// ---------------------------------------------------------------------- 2FA

/** An otpauth:// address, read as far as the code it makes and its label. */
function readOtpauth(raw: string): { key: string; label: string } | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "otpauth:") return null;
  const p = url.searchParams;
  const secret = cleanSecret(p.get("secret") ?? "");
  const kind = url.hostname.toLowerCase() || url.pathname.split("/")[0]?.toLowerCase() || "totp";
  const key = [kind, secret, (p.get("algorithm") ?? "SHA1").toUpperCase(), p.get("digits") ?? "6", p.get("period") ?? "30"].join(":");
  let path = "";
  try {
    path = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  } catch {
    path = url.pathname.replace(/^\/+/, "");
  }
  const [labelIssuer, account] = path.includes(":") ? [path.slice(0, path.indexOf(":")), path.slice(path.indexOf(":") + 1)] : ["", path];
  const issuer = (p.get("issuer") ?? labelIssuer).trim();
  const label = [issuer, account.trim()].filter(Boolean).join(": ");
  return { key, label };
}

const cleanSecret = (s: string): string => s.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();

/**
 * What makes two 2FA entries the same: the secret and the settings that change the code. The same secret saved as a
 * bare key and as an otpauth:// address with the defaults is the same.
 */
export function totpKey(raw: string): string {
  const s = raw.trim();
  const uri = readOtpauth(s);
  if (uri) return uri.key;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return s;
  return ["totp", cleanSecret(s), "SHA1", "6", "30"].join(":");
}

function totpChoices(entries: readonly DuplicateEntry[]): TotpChoice[] {
  const byKey = new Map<string, TotpChoice>();
  for (const e of entries) {
    const raw = e.item.login?.totp?.trim();
    if (!raw) continue;
    const key = totpKey(raw);
    const known = byKey.get(key);
    if (known) {
      known.from.push(e.id);
      continue;
    }
    const label = readOtpauth(raw)?.label || e.item.name || "Untitled";
    byKey.set(key, { secret: e.item.login?.totp ?? raw, label, from: [e.id] });
  }
  return [...byKey.values()];
}

// -------------------------------------------------------------------- merge

export interface MergeChoice {
  /** The combined login's name (one of the group's, the keeper's by default). */
  name?: string;
  /** The 2FA secret to keep (one of `totps`). Required when the group has different ones. */
  totp?: string | null;
}

export class MergeError extends Error {}
export const PICK_TOTP = "Choose which 2FA code to keep.";

/** The notes of the combined login: equal or one empty → that one, else the keeper's, a blank line, the others'. */
export function mergeNotes(notes: readonly string[]): string {
  const kept: string[] = [];
  // A note already held whole (a login combined before, then again) isn't added twice.
  for (const n of notes) if (n && n.trim() && !kept.some((k) => k === n || k.split("\n\n").includes(n))) kept.push(n);
  return kept.join("\n\n");
}

/** The combined login, from the keeper with every other login's websites, passkeys, notes, fields, history and tags added. */
export function mergeGroup<T extends DuplicateEntry>(group: DuplicateGroup<T>, choice: MergeChoice = {}): Item {
  const keeper = group.keeper.item;
  const items = group.entries.map((e) => e.item);
  const login = keeper.login;
  if (!login) throw new MergeError("Only logins can be combined.");

  let totp: string | null;
  if (group.differentTotp) {
    const picked = group.totps.find((t) => t.secret === choice.totp);
    if (!picked) throw new MergeError(PICK_TOTP);
    totp = picked.secret;
  } else {
    totp = group.totps[0]?.secret ?? null;
  }

  const urls: LoginUrl[] = [];
  const seenUrls = new Set<string>();
  for (const i of items)
    for (const u of i.login?.urls ?? []) {
      if (typeof u?.url !== "string" || !u.url.trim()) continue;
      const key = `${u.url}\u0000${u.match}`;
      if (seenUrls.has(key)) continue;
      seenUrls.add(key);
      urls.push({ ...u });
    }

  const passkeys: Passkey[] = [];
  const seenKeys = new Set<string>();
  for (const i of items)
    for (const p of i.login?.passkeys ?? []) {
      if (seenKeys.has(p.credential_id)) continue;
      seenKeys.add(p.credential_id);
      passkeys.push(p);
    }

  const fields: Field[] = [];
  const seenFields = new Set<string>();
  for (const i of items)
    for (const f of i.fields ?? []) {
      const key = `${f.name}\u0000${f.value}`;
      if (seenFields.has(key)) continue;
      seenFields.add(key);
      fields.push(f);
    }

  const history: Item["password_history"] = [];
  const seenHistory = new Set<string>();
  for (const i of items)
    for (const h of i.password_history ?? []) {
      const key = `${h.changed_at}\u0000${h.password}`;
      if (seenHistory.has(key)) continue;
      seenHistory.add(key);
      history.push(h);
    }
  history.sort((a, b) => b.changed_at - a.changed_at);

  const tags: string[] = [];
  for (const i of items) for (const t of i.tags ?? []) if (!tags.includes(t)) tags.push(t);

  const names = items.map((i) => i.name);
  const name = choice.name !== undefined && names.includes(choice.name) ? choice.name : keeper.name;

  return {
    ...keeper,
    name,
    notes: mergeNotes(items.map((i) => i.notes ?? "")),
    favorite: items.some((i) => i.favorite),
    tags,
    login: { ...login, urls, totp, passkeys },
    fields,
    password_history: history.slice(0, HISTORY_CAP),
  };
}

// ------------------------------------------------------------------ combine

/** Names in plain words: "A", "A and B", "A, B and C". */
export function joinNames(names: readonly string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

/** The ids of a group, sorted: what "Keep separate" remembers (the group shows again when its members change). */
export const groupKey = (group: { entries: readonly { id: string }[] }): string =>
  group.entries
    .map((e) => e.id)
    .sort()
    .join(",");

/** The vault's write functions and its current copy (vault.ts `updateItem`, `trashItem`, the state's items). */
export interface CombineDeps<T extends DuplicateEntry> {
  update: (entry: T, item: Item) => Promise<void>;
  trash: (id: string) => Promise<void>;
  /** The login as the vault holds it now (after the previous step), or undefined when it is gone. */
  current: (id: string) => T | undefined;
  /** Whether a change of this login waits to be sent (offline): then the device isn't online and combining stops. */
  waiting?: (id: string) => boolean;
  /** Called before each step: saving the combined login, then moving `left` logins to the trash. */
  progress?: (step: { kind: "save" } | { kind: "trash"; left: number }) => void;
}

export const GROUP_CHANGED = "These logins changed since this list was made, so nothing was combined. Check the updated list and try again.";
export const COMBINE_OFFLINE = "You're offline. Combining logins needs a connection to your server.";

/** Combining stopped after the keeper was saved: it holds everything, but `remaining` are still to be moved to the trash. */
export class CombineIncomplete<T extends DuplicateEntry = DuplicateEntry> extends Error {
  constructor(
    readonly remaining: T[],
    readonly cause?: unknown,
  ) {
    super(`The combined login is saved, but ${joinNames(remaining.map((e) => e.item.name || "Untitled"))} couldn't be moved to the trash. Try again.`);
  }
}

const unchanged = (seen: DuplicateEntry, now: DuplicateEntry | undefined): boolean =>
  !!now && now.revision === seen.revision && now.deletedAt === null && now.vaultId === seen.vaultId;

/**
 * Save `merged` over the keeper (an ordinary edit: `rev` counts up, the manifest as any edit), then move each other
 * login to the trash (restorable). Nothing is written when any login changed since the group was made (GROUP_CHANGED).
 * A failure after the keeper was saved throws `CombineIncomplete` naming the logins still to be trashed; a revision
 * conflict there stops too (nothing is overwritten or trashed unseen).
 */
export async function combineGroup<T extends DuplicateEntry>(group: DuplicateGroup<T>, merged: Item, deps: CombineDeps<T>): Promise<void> {
  if (!group.entries.every((e) => unchanged(e, deps.current(e.id)))) throw new Error(GROUP_CHANGED);
  const keeper = deps.current(group.keeper.id) as T;
  deps.progress?.({ kind: "save" });
  await deps.update(keeper, merged);
  if (deps.waiting?.(keeper.id)) throw new CombineIncomplete(group.entries.slice(1), new Error(COMBINE_OFFLINE));
  const others = group.entries.slice(1);
  for (let n = 0; n < others.length; n++) {
    const seen = others[n];
    const now = deps.current(seen.id);
    // Already in the trash (another device did it): nothing left to do for it.
    if (now && now.deletedAt !== null) continue;
    if (!unchanged(seen, now)) throw new CombineIncomplete(others.slice(n), new Error(GROUP_CHANGED));
    deps.progress?.({ kind: "trash", left: others.length - n });
    try {
      await deps.trash(seen.id);
    } catch (e) {
      throw new CombineIncomplete(others.slice(n), e);
    }
  }
}
