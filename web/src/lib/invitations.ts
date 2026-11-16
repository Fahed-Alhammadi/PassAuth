/**
 * Vault invitations (servers with the `vault_invitations` feature). Sharing a vault with someone who isn't a member yet
 * makes an invitation; nothing of the vault reaches their apps until they accept it, so nobody can put a vault, or
 * logins planted in it, into someone's apps without their consent. Every `/sync` answer, full or delta, lists the
 * pending invitations in full, each with the vault key sealed to the account (opened only to read the vault's name) and
 * the sharer's public key, whose fingerprint the user compares with the sharer out of band before accepting.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `invitations.test.ts`; `vault.ts` opens the sealed keys.
 */
import type { Role, SyncInvitation } from "./types";

/** An invitation as the app shows it. */
export interface Invitation {
  vaultId: string;
  role: Role;
  /** The vault's name; null when this account's keys can't open the invitation (then it can only be declined). */
  name: string | null;
  /** Who shared the vault; null once their account is deleted. */
  invitedBy: { id: string; email: string; name: string; publicKey: string } | null;
  /** Unix seconds; null when the server didn't say. */
  invitedAt: number | null;
}

const text = (v: unknown): string => (typeof v === "string" ? v : "");

/**
 * The `invitations` of a `/sync` answer. Servers without the feature send none (an empty list); an entry without a
 * vault id, sealed key, encrypted name or role is left out, and a vault listed twice counts once.
 */
export function readInvitations(value: unknown): SyncInvitation[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const out: SyncInvitation[] = [];
  for (const raw of value) {
    if (!raw || typeof raw !== "object") continue;
    const v = raw as Record<string, unknown>;
    const vaultId = v.vault_id;
    if (typeof vaultId !== "string" || !vaultId || seen.has(vaultId)) continue;
    if (typeof v.wrapped_key !== "string" || !v.wrapped_key || typeof v.meta !== "string" || !v.meta) continue;
    // A role this app doesn't know yet is kept (and shown as the server names it), so the invitation can still be answered.
    if (typeof v.role !== "string" || !v.role) continue;
    const by = v.invited_by;
    const invitedBy =
      by && typeof by === "object" && typeof (by as Record<string, unknown>).id === "string"
        ? (() => {
            const b = by as Record<string, unknown>;
            return { id: b.id as string, email: text(b.email), name: text(b.name), public_key: text(b.public_key) };
          })()
        : null;
    seen.add(vaultId);
    out.push({
      vault_id: vaultId,
      role: v.role as Role,
      wrapped_key: v.wrapped_key,
      meta: v.meta,
      invited_by: invitedBy,
      invited_at: typeof v.invited_at === "number" && Number.isFinite(v.invited_at) ? v.invited_at : null,
    });
  }
  return out;
}

/**
 * The invitations as the app shows them, in the server's order (oldest first). `open` reads the vault's name with the
 * sealed key and returns null (or throws) when that isn't possible.
 */
export function openInvitations(list: SyncInvitation[], open: (inv: SyncInvitation) => string | null): Invitation[] {
  return list.map((inv) => {
    let name: string | null;
    try {
      name = open(inv);
    } catch {
      name = null;
    }
    const by = inv.invited_by;
    return {
      vaultId: inv.vault_id,
      role: inv.role,
      name: typeof name === "string" ? name : null,
      invitedBy: by ? { id: by.id, email: by.email, name: by.name, publicKey: by.public_key } : null,
      invitedAt: inv.invited_at,
    };
  });
}

/** Who shared the vault: "Alex Morgan (alex@example.com)", the email alone, or a note when their account is gone. */
export function sharerName(inv: Invitation): string {
  const by = inv.invitedBy;
  if (!by) return "Someone whose account was deleted";
  const name = by.name.trim();
  const email = by.email.trim();
  if (name && email) return `${name} (${email})`;
  return name || email || "Someone on this server";
}

/** The sharer's name alone, for running text ("Ask Alex Morgan to…"). */
export function sharerShortName(inv: Invitation): string {
  const by = inv.invitedBy;
  return by?.name.trim() || by?.email.trim() || "the person who shared it";
}

/** One quiet line for the vault list while invitations wait; null when there are none. */
export function invitationNotice(list: Invitation[]): string | null {
  if (list.length === 0) return null;
  if (list.length > 1) return `You have ${list.length} invitations to shared vaults.`;
  const inv = list[0];
  const who = inv.invitedBy ? sharerShortName(inv) : "Someone";
  return `${who} invited you to ${inv.name ? `the shared vault "${inv.name}"` : "a shared vault"}.`;
}

/** Identifies a set of invitations, so a dismissed notice comes back when a new one arrives. */
export function invitationsKey(list: Invitation[]): string {
  return list
    .map((i) => i.vaultId)
    .sort()
    .join(",");
}
