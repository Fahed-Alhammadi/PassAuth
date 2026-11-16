/**
 * Emergency access (servers with the `emergency_access` feature): someone (the grantor) names a trusted contact with an
 * account on the same server and a waiting period of 1–90 days. invited → (the contact accepts) accepted → (the
 * grantor checks the contact's fingerprint with them and seals the account key to the contact's public key) confirmed →
 * (the contact asks) requested → (the grantor approves, or the waiting period ends) approved. The grantor may reject a
 * request or end an approved access (rejected; the contact may ask again); either side may remove it.
 *
 * An approved contact can view the grantor's own vaults (not shared ones), read-only. Limits, said plainly in the app:
 * the waiting period is the server's rule, not encryption, and the account key never changes, so a contact who was
 * approved keeps what they saw.
 *
 * Pure (no WASM, no network, no React) and unit-tested in `emergency.test.ts`.
 */
import type { EncryptedItem } from "./types";

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
}

/** Shortest and longest waiting period the server accepts, in days. */
export const MIN_WAIT_DAYS = 1;
export const MAX_WAIT_DAYS = 90;
/** The waiting period offered first. */
export const DEFAULT_WAIT_DAYS = 7;

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

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
  };
}

/** `GET /emergency-access`: the contacts the account named, and the people who named it. */
export function readGrants(value: unknown): { asGrantor: Grant[]; asGrantee: Grant[] } {
  const v = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const list = (x: unknown) => (Array.isArray(x) ? x.map(readGrant).filter((g): g is Grant => g !== null) : []);
  return { asGrantor: list(v.as_grantor), asGrantee: list(v.as_grantee) };
}

/** A person's name, else their email address. */
export const personName = (p: GrantPerson): string => p.name.trim() || p.email || "Someone";

/** "1 day", "7 days". */
export const daysText = (days: number): string => `${days} ${days === 1 ? "day" : "days"}`;

/** A waiting period the server accepts: a whole number of days from 1 to 90. */
export const validWait = (days: number): boolean => Number.isInteger(days) && days >= MIN_WAIT_DAYS && days <= MAX_WAIT_DAYS;

export type Tone = "ok" | "warn" | "info";

/** What a status means to the grantor, about their contact `who`. `when` formats Unix seconds. */
export function grantorStatus(g: Grant, when: (seconds: number) => string): { label: string; text: string; tone: Tone } {
  const who = personName(g.grantee);
  switch (g.status) {
    case "invited":
      return { label: "Invited", text: `Waiting for ${who} to accept.`, tone: "info" };
    case "accepted":
      return { label: "Confirm", text: `${who} accepted. Check their fingerprint with them, then confirm them.`, tone: "warn" };
    case "confirmed":
      return { label: "Ready", text: `${who} can ask for access. You'd have ${daysText(g.waitDays)} to say no.`, tone: "ok" };
    case "requested":
      return {
        label: "Access requested",
        text:
          g.autoApproveAt !== null
            ? `${who} asked for access${g.requestedAt !== null ? ` on ${when(g.requestedAt)}` : ""}. Unless you reject it, they can view your vaults from ${when(g.autoApproveAt)}.`
            : `${who} asked for access. Unless you reject it, they can view your vaults after ${daysText(g.waitDays)}.`,
        tone: "warn",
      };
    case "approved":
      return { label: "Has access", text: `${who} can view your vaults${g.approvedAt !== null ? ` since ${when(g.approvedAt)}` : ""}.`, tone: "warn" };
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

// ------------------------------------------------------------- the vault

/** `GET /emergency-access/{id}/vault`: the sealed account key, the grantor's own vaults and all their items. */
export interface GrantorVaultData {
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
  return { sealedKey, vaults, items };
}
