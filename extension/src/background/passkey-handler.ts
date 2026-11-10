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
import { NEW_LOGIN } from "./save-plan";
import { local } from "./storage";
import { passkeySaveTargets, type PasskeyTarget } from "./passkey-targets";
import { allEntries, canWrite, createItem, ensureUnlocked, getEntry, isPersonal, updateItem, vaultName, verifyMasterPassword, type Entry } from "./vault";
import { openCentered } from "../shared/windows";

/** `credentialId`: for sign-in the chosen passkey; for creation the login to save it in (an item id, or `NEW_LOGIN`). */
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
  /**
   * Sign-in: matching passkeys. Creation: logins to save in (`preferred` = the user's own login for this exact
   * site, preselected; `vault` = the shared vault a login lives in, shown on its row).
   */
  candidates: { credentialId: string; userName: string; itemName: string; preferred?: boolean; vault?: string }[];
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
    const candidates = saveTargets(host, rpId, req.user?.name ?? "", req.user?.displayName ?? "").map((t) => ({
      credentialId: t.id,
      userName: clip(t.username),
      itemName: clip(t.name || host),
      preferred: t.preferred,
      vault: t.vault && clip(t.vault, 40),
    }));
    const decision = await confirm({ ...base, kind, userName: clip(req.user?.name ?? ""), candidates }, wait);
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
    userName: clip(p.user_name || p.user_display_name),
    itemName: clip(all.find((x) => x.passkey.credential_id === p.credential_id)?.entry.item.name ?? p.rp_id),
  }));
  const decision = await confirm({ ...base, kind, userName: "", candidates }, wait);
  if (!decision.accept) return decision.fallback ? FALLBACK : notAllowed();
  const chosen = matches.find((p) => p.credential_id === decision.credentialId) ?? matches[0];
  const { response } = await getAssertion(req, msg.origin, chosen, { uv: true });
  return { result: response };
}

/**
 * Names in the confirmation window come from the website (the passkey's user
 * name) or were once given by one: shown shortened, so a page can't blow the
 * window up or push its real content out of view. What is saved is never cut.
 */
const clip = (text: string, max = 64) => {
  const chars = [...text.replace(/\s+/g, " ").trim()];
  return chars.length > max ? `${chars.slice(0, max - 1).join("")}…` : chars.join("");
};

function allPasskeys(): { entry: Entry; passkey: Passkey }[] {
  return allEntries().flatMap((entry) => (entry.item.login?.passkeys ?? []).map((passkey) => ({ entry, passkey })));
}

/** The logins a new passkey can be saved in, best first (passkey-targets.ts). */
function saveTargets(host: string, rpId: string, userName: string, displayName: string): PasskeyTarget[] {
  const logins = allEntries()
    .filter((e) => e.item.login)
    .map((e) => ({
      id: e.id,
      name: e.item.name,
      username: e.item.login!.username,
      urls: e.item.login!.urls.map((u) => u.url),
      writable: canWrite(e),
      personal: isPersonal(e),
      vault: vaultName(e.vaultId),
    }));
  return passkeySaveTargets(logins, host, rpId, userName, displayName);
}

/** Save the passkey in the login the user chose (still one they can edit for this site), or in a new login in their own vault. */
async function storePasskey(passkey: Passkey, rpName: string, host: string, targetId: string) {
  // Only a login that is (still) one of the choices for this site; anything else becomes a new login in the user's own vault.
  const target = targetId !== NEW_LOGIN && saveTargets(host, passkey.rp_id, "", "").some((t) => t.id === targetId) ? getEntry(targetId) : undefined;
  if (target?.item.login) {
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

/**
 * Page size of the confirmation sheet, from its layout in popup.css ("decision
 * sheet"), so the window opens at its final size; the window still measures
 * the real sheet and corrects itself if a line wraps differently (Passkey.tsx).
 */
function sheetSize(p: Omit<Pending, "decide">): { width: number; height: number } {
  const creating = p.kind === "create";
  const rows = creating ? (p.candidates.length ? p.candidates.length + 1 : 0) : p.candidates.length;
  // The note is ~50 characters to a line (see the text in Passkey.tsx).
  const note = creating ? SHEET.gap + SHEET.line * Math.ceil((84 + (p.userName ? 23 + p.userName.length : 0)) / 50) : 0;
  const list = rows ? SHEET.gap + (rows > 1 ? SHEET.legend : 0) + Math.min(rows * SHEET.row + 2, SHEET.listMax) : 0;
  const password = p.needsPassword ? SHEET.gap + SHEET.password : 0;
  return { width: 380, height: SHEET.base + note + list + password };
}
/**
 * Heights in px, pinned in popup.css (`.sheet`). `base`: brand bar 48 + body padding 4 and 16 + context row 40 +
 * gap 16 + actions 80 (button 40, gap 4, quiet row 36) − 8 the quiet row gives back. `listMax`: 4½ rows, then the list scrolls.
 */
const SHEET = { base: 196, gap: 16, line: 20, row: 56, legend: 28, listMax: 254, password: 91 };

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
    // Centred over the browser window that holds the requesting tab (and so on that window's display).
    openCentered(chrome.runtime.getURL(`popup.html#passkey=${id}`), sheetSize(p), { tabId: p.tabId })
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

export async function pendingRequest(id: string) {
  const p = pending.get(id);
  if (!p) return null;
  const { decide: _decide, tabId: _t, frameId: _f, bridgeId: _b, ...info } = p;
  // The site icon comes from the user's server, which fetches it from the site. Only for a site the vault
  // already has a login for: before the user has agreed to anything, a page must not be able to make
  // the server fetch an icon for whatever host it names.
  const { server, settings } = await local.get();
  return { ...info, server, showIcons: settings.showIcons && (p.kind === "get" || p.candidates.length > 0) };
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
