/**
 * Emergency access requests and keys (`emergency.ts` has the rules, unit-tested). Confirming a contact seals this
 * account's key to the contact's public key, after the user compared the contact's fingerprint with them; viewing a
 * grantor's vault opens that sealed key as a `GrantorKey`, which opens only the grantor's own vault keys. Everything
 * decrypted stays in memory (the page's state) and every key handle is freed as soon as it has been used.
 */
import * as core from "../wasm/passauth_core";
import { ApiError, api } from "./api";
import { readGrant, readGrantorVault, readGrants, personName, type Grant } from "./emergency";
import type { Item } from "./types";
import { getAccount } from "./vault";

const LOCKED = "The vault is locked. Unlock it and try again.";
const UNEXPECTED = "The server sent an unexpected response. Try again.";
const path = (id: string, rest = "") => `/emergency-access/${encodeURIComponent(id)}${rest}`;

function grantOf(value: unknown): Grant {
  const g = readGrant(value);
  if (!g) throw new Error(UNEXPECTED);
  return g;
}

export const listGrants = async () => readGrants(await api("/emergency-access"));

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

/** The grantor's step after the contact accepted: seal this account's key to the contact's public key. */
export async function confirmContact(g: Grant): Promise<Grant> {
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  if (!g.grantee.publicKey) throw new Error(`${personName(g.grantee)}'s account has no key to confirm. Ask them to sign in once, then try again.`);
  const sealed = acct.sealAccountKeyFor(g.grantee.publicKey);
  return grantOf(await api(path(g.id, "/confirm"), { body: { sealed_key: sealed } }));
}

export const changeWait = async (id: string, waitDays: number) => grantOf(await api(path(id), { method: "PUT", body: { wait_days: waitDays } }));
export const acceptGrant = async (id: string) => grantOf(await api(path(id, "/accept"), { method: "POST" }));
export const requestAccess = async (id: string) => grantOf(await api(path(id, "/request"), { method: "POST" }));
export const approveGrant = async (id: string) => grantOf(await api(path(id, "/approve"), { method: "POST" }));
export const rejectGrant = async (id: string) => grantOf(await api(path(id, "/reject"), { method: "POST" }));

/** Remove an emergency access, from either side. Already gone counts as done. */
export async function removeGrant(id: string): Promise<void> {
  try {
    await api(path(id), { method: "DELETE" });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
}

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
 * Fetch and decrypt the vaults a grantor shared through emergency access (approved accesses only). The sealed account
 * key is opened for this, each vault key is used for its items and freed, and the grantor's key is freed at the end.
 */
export async function openGrantorVault(id: string): Promise<GrantorVault> {
  const answer = await api(path(id, "/vault"));
  const data = readGrantorVault(answer);
  const grant = readGrant((answer as { grant?: unknown } | null)?.grant);
  if (!data || !grant) throw new Error(UNEXPECTED);
  const acct = getAccount();
  if (!acct) throw new Error(LOCKED);
  let grantor: core.GrantorKey;
  try {
    grantor = core.openSealedAccountKey(acct, grant.grantor.id, data.sealedKey);
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
      let key: core.VaultKey;
      try {
        key = grantor.openVaultKey(v.id, v.wrappedKey, "account");
      } catch {
        failed += rows.length;
        continue;
      }
      try {
        let name = "Vault";
        try {
          const meta = key.decryptMeta(v.id, v.meta) as { name?: unknown } | null;
          if (typeof meta?.name === "string" && meta.name.trim()) name = meta.name;
        } catch {
          /* keep the generic name */
        }
        vaults.push({ id: v.id, name });
        for (const r of rows) {
          try {
            items.push({ id: r.row.id, vaultId: v.id, item: key.decryptItem(r.row) as Item, deletedAt: r.deletedAt });
          } catch {
            failed++;
          }
        }
      } finally {
        key.free();
      }
    }
  } finally {
    grantor.free();
  }
  const byName = new Intl.Collator(undefined, { sensitivity: "base" });
  items.sort((a, b) => byName.compare(a.item.name, b.item.name));
  return { grant, vaults, items, failed };
}
