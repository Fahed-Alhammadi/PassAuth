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
} from "./passkeys";
import type { CreateRequest, GetRequest } from "../shared/passkey-types";
import { allEntries, canWrite, createItem, ensureUnlocked, updateItem, verifyMasterPassword, type Entry } from "./vault";

/** `credentialId`: for sign-in the chosen passkey; for creation the login to save it in (an item id, or `NEW_LOGIN`). */
type Decision = { accept: boolean; credentialId?: string; fallback?: boolean; verified?: boolean };

/** Save target meaning "create a new login" (never an item id: those are UUIDs). */
export const NEW_LOGIN = "new";
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
  /** Sign-in: matching passkeys. Creation: logins to save in (`preferred` = this exact site, preselected). */
  candidates: { credentialId: string; userName: string; itemName: string; preferred?: boolean }[];
  /** The site requires user verification and the master password wasn't entered recently. */
  needsPassword: boolean;
  tabId: number;
  frameId: number;
  bridgeId: string;
  decide: (d: Decision) => void;
}

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
  // User verification: PassAuth is unlocked (checked above), which took the master password, and
  // the vault timeout locks it again, like a platform authenticator unlocked with the device PIN.
  // So no extra password prompt; the user still approves each request in PassAuth's window.
  const needsPassword = false;
  const base = { origin: msg.origin, rpId, needsPassword, tabId: msg.tabId, frameId: msg.frameId, bridgeId: msg.bridgeId };
  const wait = timeoutOf(msg.options);

  if (kind === "create") {
    const req = msg.options as CreateRequest;
    if (!supportsCreateRequest(req)) return FALLBACK;
    const host = new URL(msg.origin).hostname.toLowerCase();
    const targets = saveTargets(host, rpId, req.user?.name ?? "", req.user?.displayName ?? "");
    const candidates = targets.map((e) => ({
      credentialId: e.id,
      userName: e.item.login!.username,
      itemName: e.item.name || host,
      preferred: loginHosts(e).includes(host),
    }));
    const decision = await confirm({ ...base, kind, userName: req.user?.name ?? "", candidates }, wait);
    if (!decision.accept) return decision.fallback ? FALLBACK : notAllowed();
    // Checked after the user's consent so a site can't silently probe the vault.
    if (excludedPasskeyExists(req, msg.origin, allPasskeys().map((x) => x.passkey))) {
      return { error: { name: "InvalidStateError", message: "A passkey for this account is already saved in PassAuth." } };
    }
    const { passkey, response } = await createPasskey(req, msg.origin, { uv: true });
    await storePasskey(passkey, req.rp?.name ?? rpId, host, decision.credentialId ?? NEW_LOGIN);
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
  const { response } = await getAssertion(req, msg.origin, chosen, { uv: true });
  return { result: response };
}

function allPasskeys(): { entry: Entry; passkey: Passkey }[] {
  return allEntries().flatMap((entry) => (entry.item.login?.passkeys ?? []).map((passkey) => ({ entry, passkey })));
}

/** Hostnames of a login's URLs (scheme optional), lowercase, without a trailing dot. */
function loginHosts(e: Entry): string[] {
  return (e.item.login?.urls ?? []).flatMap((u) => {
    try {
      return [new URL(u.url.includes("://") ? u.url : `https://${u.url}`).hostname.toLowerCase().replace(/\.$/, "")];
    } catch {
      return [];
    }
  });
}

/**
 * Logins a new passkey can be saved in: ones you can edit whose website is this
 * exact host, the RP ID, or a subdomain of the RP ID (where the passkey also works).
 * Never just "the same base domain": cloudy.example.com and bazarr.example.com are
 * different sites. Best first: this exact host, then a matching user name.
 */
function saveTargets(host: string, rpId: string, userName: string, displayName: string): Entry[] {
  const rp = rpId.toLowerCase();
  const names = [userName, displayName].map((n) => n.trim().toLowerCase()).filter(Boolean);
  const score = (e: Entry) => {
    const hosts = loginHosts(e);
    const user = e.item.login!.username.trim().toLowerCase();
    return (hosts.includes(host) ? 2 : 0) + (user && names.some((n) => n === user || n === user.split("@")[0]) ? 1 : 0);
  };
  return allEntries()
    .filter((e) => e.item.login && canWrite(e))
    .filter((e) => loginHosts(e).some((h) => h === host || h === rp || h.endsWith(`.${rp}`)))
    .sort((a, b) => score(b) - score(a) || a.item.name.localeCompare(b.item.name));
}

/** Save the passkey in the login the user chose (still one they can edit for this site), or in a new login in their own vault. */
async function storePasskey(passkey: Passkey, rpName: string, host: string, targetId: string) {
  const target = targetId === NEW_LOGIN ? undefined : saveTargets(host, passkey.rp_id, "", "").find((e) => e.id === targetId);
  if (target) {
    const login = target.item.login!;
    await updateItem(target, { ...target.item, login: { ...login, passkeys: [...login.passkeys, passkey] } });
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const item: Item = {
    name: rpName || passkey.rp_id,
    notes: "",
    favorite: false,
    folder: null,
    tags: [],
    login: { username: passkey.user_name, password: "", urls: [{ url: `https://${host}`, match: "default" }], totp: null, passkeys: [passkey] },
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

/** Room for the password field and the account / "Save in" list (capped; the window scrolls beyond that). */
function windowHeight(p: Omit<Pending, "decide">): number {
  const rows = Math.min(p.candidates.length + (p.kind === "create" && p.candidates.length ? 1 : 0), 5);
  return Math.min(760, (p.needsPassword ? 600 : 520) + rows * 60);
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
      .create({ url: chrome.runtime.getURL(`popup.html#passkey=${id}`), type: "popup", width: 380, height: windowHeight(p), focused: true })
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
