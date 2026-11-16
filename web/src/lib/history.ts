/**
 * Item history (servers with the `item_history` feature). Before an item is edited or moved to the trash, the server
 * keeps the item as it was stored (still encrypted, with the vault key of that time) as a version: the newest
 * `item_versions_kept` per item, listed newest first (`GET /items/{id}/versions`) and fetched one by one
 * (`GET /items/{id}/versions/{seq}`). Restoring a version is an ordinary update with its content, so the content it
 * replaces becomes a version in turn. A vault key replacement deletes the vault's versions and a move to another vault
 * deletes the item's: history starts over then.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `history.test.ts`; `vault.ts` decrypts and restores.
 */
import { mergeAttachments, setAttachments } from "./attachments";
import type { Item, Passkey } from "./types";

/** Who saved a version's content: null when unknown (saved before history existed). */
export interface VersionAuthor {
  id: string;
  /** Null once their account is deleted. */
  email: string | null;
  name: string | null;
}

export interface ItemVersion {
  /** The vault's write number of the saved content: unique per item, newer versions have higher numbers. */
  seq: number;
  /** When this content was saved (Unix seconds). */
  savedAt: number;
  savedBy: VersionAuthor | null;
}

/** One version as stored: encrypted like an item, with the vault key it had when it was saved. */
export interface StoredVersion extends ItemVersion {
  vaultId: string;
  itemKey: string;
  data: string;
}

const nullableText = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const isWhole = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

function readAuthor(v: unknown): VersionAuthor | null {
  if (!v || typeof v !== "object") return null;
  const a = v as Record<string, unknown>;
  return typeof a.id === "string" && a.id ? { id: a.id, email: nullableText(a.email), name: nullableText(a.name) } : null;
}

function readOne(v: unknown): ItemVersion | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (!isWhole(r.seq) || typeof r.saved_at !== "number" || !Number.isFinite(r.saved_at)) return null;
  return { seq: r.seq, savedAt: r.saved_at, savedBy: readAuthor(r.saved_by) };
}

/** `GET /items/{id}/versions` → the versions, newest first; malformed entries and repeated numbers left out. */
export function readVersions(body: unknown): ItemVersion[] {
  const list = body && typeof body === "object" ? (body as { versions?: unknown }).versions : undefined;
  if (!Array.isArray(list)) return [];
  const bySeq = new Map<number, ItemVersion>();
  for (const raw of list) {
    const v = readOne(raw);
    if (v && !bySeq.has(v.seq)) bySeq.set(v.seq, v);
  }
  return [...bySeq.values()].sort((a, b) => b.seq - a.seq);
}

/** `GET /items/{id}/versions/{seq}` → the stored version, or null when the answer isn't one. */
export function readVersion(body: unknown): StoredVersion | null {
  const v = readOne(body);
  if (!v) return null;
  const r = body as Record<string, unknown>;
  if (typeof r.vault_id !== "string" || !r.vault_id || typeof r.item_key !== "string" || !r.item_key || typeof r.data !== "string" || !r.data) return null;
  return { ...v, vaultId: r.vault_id, itemKey: r.item_key, data: r.data };
}

/** Who saved it, for "Saved … by …": "you", their name or email, "a deleted account", or null when unknown. */
export function authorName(by: VersionAuthor | null, me: string): string | null {
  if (!by) return null;
  if (by.id === me) return "you";
  return by.name?.trim() || by.email || "a deleted account";
}

/** "Saved 12 Nov 2026, 14:03 by Alex Morgan" (`when` formats Unix seconds). */
export function versionLabel(v: ItemVersion, me: string, when: (seconds: number) => string): string {
  const by = authorName(v.savedBy, me);
  return `Saved ${when(v.savedAt)}${by ? ` by ${by}` : ""}`;
}

/** Most entries a login's password history keeps (as when editing). */
const HISTORY_MAX = 20;

/**
 * The content to save when restoring `version` over `current`: the version as it was, with the item's creation time,
 * and the password history of both (newest first, each password once), so no earlier password is forgotten. The
 * update itself then adds the password being replaced, as any edit does. Attached files of both are listed (the item's
 * own first), so none of its files is left without an item; one deleted since shows as missing.
 */
export function restoredItem(version: Item, current: Item): Item {
  const files = mergeAttachments(current, version);
  const restored: Item = setAttachments({ ...structuredClone(version), created_at: current.created_at || version.created_at }, files);
  const seen = new Set<string>();
  restored.password_history = [...(current.password_history ?? []), ...(version.password_history ?? [])]
    .filter((h) => h && typeof h.password === "string")
    .sort((a, b) => (b.changed_at ?? 0) - (a.changed_at ?? 0))
    .filter((h) => {
      if (seen.has(h.password)) return false;
      seen.add(h.password);
      return true;
    })
    .slice(0, HISTORY_MAX);
  return restored;
}

/** Passkeys the item has now that the version doesn't: restoring it would remove them (they stay in the history). */
export function passkeysMissingFrom(version: Item, current: Item): Passkey[] {
  const kept = new Set((version.login?.passkeys ?? []).map((p) => p.credential_id));
  return (current.login?.passkeys ?? []).filter((p) => !kept.has(p.credential_id));
}
