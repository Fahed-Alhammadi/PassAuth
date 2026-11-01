/**
 * Routes WebAuthn requests from pages to the authenticator, asking the user
 * to confirm in a small PassAuth window first (user presence + verification:
 * the vault is unlocked with the master password).
 */
import type { Item, Passkey } from "@web/lib/types";
import { createPasskey, effectiveRpId, errorReply, excludedPasskeyExists, getAssertion, matchingPasskeys, supportsCreateRequest } from "./passkeys";
import type { CreateRequest, GetRequest } from "../shared/passkey-types";
import { allEntries, createItem, ensureUnlocked, updateItem, type Entry } from "./vault";
import { baseDomain } from "./urls";

type Decision = { accept: boolean; credentialId?: string; fallback?: boolean };
type Reply = { result: unknown } | { fallback: true } | { error: { name: string; message: string } };

interface Pending {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string }[];
  decide: (d: Decision) => void;
}

const pending = new Map<string, Pending>();
const notAllowed = (message = "The request was cancelled.") => ({ error: { name: "NotAllowedError", message } });

export async function handlePasskey(msg: { type: string; options: any; origin: string; topLevel: boolean }): Promise<Reply> {
  try {
    return await handle(msg);
  } catch (e) {
    return errorReply(e) as Reply;
  }
}

async function handle(msg: { type: string; options: any; origin: string; topLevel: boolean }): Promise<Reply> {
  if (!msg.topLevel) return { fallback: true };
  if (!(await ensureUnlocked())) return { fallback: true };

  let rpId: string;
  try {
    rpId = effectiveRpId(msg.type === "passkey:create" ? msg.options.rp?.id : msg.options.rpId, msg.origin);
  } catch (e) {
    return { error: { name: "SecurityError", message: e instanceof Error ? e.message : "Invalid relying party." } };
  }

  if (msg.type === "passkey:create") {
    const req = msg.options as CreateRequest;
    if (!supportsCreateRequest(req)) return { fallback: true };
    const decision = await confirm({ kind: "create", origin: msg.origin, rpId, userName: req.user?.name ?? "", candidates: [] });
    if (!decision.accept) return decision.fallback ? { fallback: true } : notAllowed();
    // Checked after the user's consent so a site can't silently probe the vault.
    if (excludedPasskeyExists(req, msg.origin, allPasskeys().map((x) => x.passkey))) {
      return { error: { name: "InvalidStateError", message: "A passkey for this account is already saved in PassAuth." } };
    }
    const { passkey, response } = await createPasskey(req, msg.origin);
    await storePasskey(passkey, req.rp?.name ?? rpId);
    return { result: response };
  }

  const req = msg.options as GetRequest;
  const all = allPasskeys();
  const matches = matchingPasskeys(req, msg.origin, all.map((x) => x.passkey));
  if (!matches.length) return { fallback: true };
  const candidates = matches.map((p) => ({
    credentialId: p.credential_id,
    userName: p.user_name || p.user_display_name,
    itemName: all.find((x) => x.passkey.credential_id === p.credential_id)?.entry.item.name ?? p.rp_id,
  }));
  const decision = await confirm({ kind: "get", origin: msg.origin, rpId, userName: "", candidates });
  if (!decision.accept) return decision.fallback ? { fallback: true } : notAllowed();
  const chosen = matches.find((p) => p.credential_id === decision.credentialId) ?? matches[0];
  const { response } = await getAssertion(req, msg.origin, chosen);
  return { result: response };
}

function allPasskeys(): { entry: Entry; passkey: Passkey }[] {
  return allEntries().flatMap((entry) => (entry.item.login?.passkeys ?? []).map((passkey) => ({ entry, passkey })));
}

/** Attach to an existing login for the same site and username, or create one. */
async function storePasskey(passkey: Passkey, rpName: string) {
  const site = baseDomain(passkey.rp_id);
  const existing = allEntries().find(
    (e) =>
      e.item.login &&
      e.item.login.username.toLowerCase() === passkey.user_name.toLowerCase() &&
      e.item.login.urls.some((u) => {
        try {
          return baseDomain(new URL(u.url.includes("://") ? u.url : `https://${u.url}`).hostname) === site;
        } catch {
          return false;
        }
      }),
  );
  if (existing) {
    const login = existing.item.login!;
    await updateItem(existing, { ...existing.item, login: { ...login, passkeys: [...login.passkeys, passkey] } });
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const item: Item = {
    name: rpName || passkey.rp_id,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: passkey.user_name, password: "", urls: [{ url: `https://${passkey.rp_id}`, match: "domain" }], totp: null, passkeys: [passkey] },
    card: null,
    identity: null,
    ssh_key: null,
    fields: [],
    password_history: [],
    created_at: now,
    updated_at: now,
  };
  await createItem(item);
}

async function confirm(p: Omit<Pending, "decide">): Promise<Decision> {
  const id = crypto.randomUUID();
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL(`popup.html#passkey=${id}`),
    type: "popup",
    width: 380,
    height: 520,
    focused: true,
  });
  const winId = win?.id;
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish({ accept: false }), 120_000);
    const onRemoved = (windowId: number) => windowId === winId && finish({ accept: false });
    function finish(d: Decision) {
      clearTimeout(timer);
      chrome.windows.onRemoved.removeListener(onRemoved);
      pending.delete(id);
      if (winId !== undefined) chrome.windows.remove(winId).catch(() => {});
      resolve(d);
    }
    chrome.windows.onRemoved.addListener(onRemoved);
    pending.set(id, { ...p, decide: finish });
  });
}

export function pendingRequest(id: string) {
  const p = pending.get(id);
  if (!p) return null;
  const { decide: _decide, ...info } = p;
  return info;
}

export function decide(id: string, accept: boolean, credentialId?: string, fallback?: boolean) {
  pending.get(id)?.decide({ accept, credentialId, fallback });
}
