/**
 * Routes WebAuthn requests from pages to the authenticator, asking the user
 * to confirm in a small PassAuth window first (user presence). User
 * verification is reported only when the master password was entered for this
 * request or within the last few minutes; a site that requires it gets a
 * master-password prompt in that window.
 */
import type { Item, Passkey } from "@web/lib/types";
import {
  createPasskey,
  effectiveRpId,
  errorReply,
  excludedPasskeyExists,
  getAssertion,
  matchingPasskeys,
  PasskeyError,
  supportsCreateRequest,
  uvRequired,
} from "./passkeys";
import type { CreateRequest, GetRequest } from "../shared/passkey-types";
import { allEntries, canWrite, createItem, ensureUnlocked, recentlyVerified, updateItem, verifyMasterPassword, type Entry } from "./vault";
import { baseDomain } from "./urls";

type Decision = { accept: boolean; credentialId?: string; fallback?: boolean; verified?: boolean };
type Reply = { result: unknown } | { fallback: true } | { error: { name: string; message: string } };

export interface PasskeyMessage {
  type: string;
  options: any;
  origin: string;
  topLevel: boolean;
  tabId: number;
  frameId: number;
  /** The page bridge's request id, so an abort on the page can cancel the confirmation. */
  bridgeId: string;
}

interface Pending {
  kind: "create" | "get";
  origin: string;
  rpId: string;
  userName: string;
  candidates: { credentialId: string; userName: string; itemName: string }[];
  /** The site requires user verification and the master password wasn't entered recently. */
  needsPassword: boolean;
  tabId: number;
  frameId: number;
  bridgeId: string;
  decide: (d: Decision) => void;
}

/** How recently the master password must have been entered to report "user verified". */
const UV_WINDOW_MS = 5 * 60_000;
// Same bounds as the page shim (page/webauthn.ts), so the window never outlives the page's own timeout.
const DEFAULT_TIMEOUT_MS = 120_000;
const MIN_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 600_000;

const pending = new Map<string, Pending>();
const FALLBACK = { fallback: true } as const;
const notAllowed = (message = "The request was cancelled.") => ({ error: { name: "NotAllowedError", message } });

function timeoutOf(options: any): number {
  const t = typeof options?.timeout === "number" && Number.isFinite(options.timeout) ? options.timeout : DEFAULT_TIMEOUT_MS;
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, t));
}

export async function handlePasskey(msg: PasskeyMessage): Promise<Reply> {
  // Before the user has seen anything, any problem (locked, server down, odd
  // request) hands the request to the browser's own authenticators.
  if (!msg.topLevel || !(await ensureUnlocked().catch(() => false))) return FALLBACK;
  // One confirmation window per tab: a page can't stack windows or steal focus repeatedly.
  if ([...pending.values()].some((p) => p.tabId === msg.tabId)) return notAllowed("Another passkey request is already open in this tab.");
  try {
    return await handle(msg);
  } catch (e) {
    return errorReply(e) as Reply;
  }
}

async function handle(msg: PasskeyMessage): Promise<Reply> {
  let rpId: string;
  try {
    rpId = effectiveRpId(msg.type === "passkey:create" ? msg.options.rp?.id : msg.options.rpId, msg.origin);
  } catch (e) {
    if (e instanceof PasskeyError) return { error: { name: e.name, message: e.message } };
    return FALLBACK;
  }
  const kind = msg.type === "passkey:create" ? "create" : "get";
  const recent = await recentlyVerified(UV_WINDOW_MS);
  const needsPassword = uvRequired(kind, msg.options) && !recent;
  const base = { origin: msg.origin, rpId, needsPassword, tabId: msg.tabId, frameId: msg.frameId, bridgeId: msg.bridgeId };
  const wait = timeoutOf(msg.options);

  if (kind === "create") {
    const req = msg.options as CreateRequest;
    if (!supportsCreateRequest(req)) return FALLBACK;
    const decision = await confirm({ ...base, kind, userName: req.user?.name ?? "", candidates: [] }, wait);
    if (!decision.accept) return decision.fallback ? FALLBACK : notAllowed();
    // Checked after the user's consent so a site can't silently probe the vault.
    if (excludedPasskeyExists(req, msg.origin, allPasskeys().map((x) => x.passkey))) {
      return { error: { name: "InvalidStateError", message: "A passkey for this account is already saved in PassAuth." } };
    }
    const { passkey, response } = await createPasskey(req, msg.origin, { uv: recent || !!decision.verified });
    await storePasskey(passkey, req.rp?.name ?? rpId);
    return { result: response };
  }

  const req = msg.options as GetRequest;
  const all = allPasskeys();
  let matches: Passkey[];
  try {
    matches = matchingPasskeys(req, msg.origin, all.map((x) => x.passkey));
  } catch (e) {
    if (e instanceof PasskeyError) return { error: { name: e.name, message: e.message } };
    return FALLBACK;
  }
  if (!matches.length) return FALLBACK;
  const candidates = matches.map((p) => ({
    credentialId: p.credential_id,
    userName: p.user_name || p.user_display_name,
    itemName: all.find((x) => x.passkey.credential_id === p.credential_id)?.entry.item.name ?? p.rp_id,
  }));
  const decision = await confirm({ ...base, kind, userName: "", candidates }, wait);
  if (!decision.accept) return decision.fallback ? FALLBACK : notAllowed();
  const chosen = matches.find((p) => p.credential_id === decision.credentialId) ?? matches[0];
  const { response } = await getAssertion(req, msg.origin, chosen, { uv: recent || !!decision.verified });
  return { result: response };
}

function allPasskeys(): { entry: Entry; passkey: Passkey }[] {
  return allEntries().flatMap((entry) => (entry.item.login?.passkeys ?? []).map((passkey) => ({ entry, passkey })));
}

/** Attach to an existing login you can edit for the same site and username, or create one in your own vault. */
async function storePasskey(passkey: Passkey, rpName: string) {
  const site = baseDomain(passkey.rp_id);
  const existing = allEntries().find(
    (e) =>
      e.item.login &&
      canWrite(e) &&
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
    login: { username: passkey.user_name, password: "", urls: [{ url: `https://${passkey.rp_id}`, match: "default" }], totp: null, passkeys: [passkey] },
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

/**
 * Open the confirmation window. It keeps a port to this worker (with a
 * heartbeat), so the worker stays awake while the user decides.
 */
async function confirm(p: Omit<Pending, "decide">, timeoutMs: number): Promise<Decision> {
  const id = crypto.randomUUID();
  // Registered before the window opens, so the window can always find the request.
  let finish: (d: Decision) => void = () => {};
  const result = new Promise<Decision>((resolve) => {
    let winId: number | undefined;
    const timer = setTimeout(() => finish({ accept: false }), timeoutMs);
    const onRemoved = (windowId: number) => windowId === winId && finish({ accept: false });
    finish = (d: Decision) => {
      if (!pending.has(id)) return;
      clearTimeout(timer);
      chrome.windows.onRemoved.removeListener(onRemoved);
      pending.delete(id);
      if (winId !== undefined) chrome.windows.remove(winId).catch(() => {});
      resolve(d);
    };
    chrome.windows.onRemoved.addListener(onRemoved);
    pending.set(id, { ...p, decide: (d) => finish(d) });
    chrome.windows
      .create({ url: chrome.runtime.getURL(`popup.html#passkey=${id}`), type: "popup", width: 380, height: p.needsPassword ? 600 : 520, focused: true })
      .then(
        (win) => {
          winId = win?.id;
          if (!pending.has(id) && winId !== undefined) chrome.windows.remove(winId).catch(() => {});
        },
        () => finish({ accept: false }),
      );
  });
  return result;
}

export function pendingRequest(id: string) {
  const p = pending.get(id);
  if (!p) return null;
  const { decide: _decide, tabId: _t, frameId: _f, bridgeId: _b, ...info } = p;
  return info;
}

export async function decide(id: string, accept: boolean, credentialId?: string, fallback?: boolean, password?: string) {
  const p = pending.get(id);
  if (!p) throw new Error("This request has expired. Try again on the website.");
  let verified = false;
  if (accept && p.needsPassword) {
    if (!password) throw new Error("Enter your master password to continue.");
    await verifyMasterPassword(password);
    verified = true;
  }
  p.decide({ accept, credentialId, fallback, verified });
}

/** The page aborted or timed out its request: close the window without creating or using anything. */
export function cancelPasskey(tabId: number, frameId: number, bridgeId: string) {
  for (const p of pending.values()) if (p.tabId === tabId && p.frameId === frameId && p.bridgeId === bridgeId) p.decide({ accept: false });
}
