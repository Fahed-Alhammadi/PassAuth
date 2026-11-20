/**
 * Routes WebAuthn requests from pages to the authenticator, asking the user
 * to confirm in a small PassAuth window first (user presence). User
 * verification (the UV flag) is reported only when the master password was
 * entered for this request, or in this browser session within the last
 * VERIFIED_MS (unlock, sign-in, reauth), or the vault timeout is "never" (the
 * unlocked vault counts, also with keys restored from disk; `passkeyVerified`).
 * A site that requires it gets a master-password field in that window when
 * neither holds; "preferred" gets UV only when one holds; "discouraged" never.
 *
 * A page can ask to sign in without a user gesture (a two-step page asks as it
 * loads), but not over and over against the user: after the user cancels in a
 * tab (Cancel, closing the window, letting it time out) or the page aborts its
 * own request, sign-in requests from that tab without a fresh click or key
 * press are refused at once for a while (30 s, doubling with every further
 * cancel up to 10 minutes; `backedOff`). A request that comes with a gesture
 * always opens the window.
 */
import type { Item, Passkey } from "@web/lib/types";
import { AppError, codeOf, EXPIRED, INSUFFICIENT_STORAGE, PASSWORD_REQUIRED, QUOTA_EXCEEDED } from "../shared/errors";
import { capPasskeyNames } from "../shared/limits";
import { log, logged, loggedAs } from "../shared/log";
import { pageText } from "../shared/page-text";
import type { CreateRequest, GetRequest, PasskeyRuntimeReply } from "../shared/passkey-types";
import type { PasskeyRequestInfo } from "../shared/types";
import { openCentered } from "../shared/windows";
import { iconsShown } from "./api";
import { initCore } from "./core";
import {
  createPasskey,
  effectiveRpId,
  errorReply,
  excludedPasskeyExists,
  getAssertion,
  matchingPasskeys,
  PasskeyError,
  supportsCreateRequest,
  type UserVerification,
  userVerification,
} from "./passkeys";
import { NEW_LOGIN, type PasskeyTarget, passkeyDefaultTarget, passkeySaveTargets } from "./site";
import { local } from "./storage";
import { notifyTab } from "./toast";
import { isKeyPageRequest } from "./two-step-key";
import { allEntries, canWrite, createItem, type Entry, ensureUnlocked, getEntry, isPersonal, owner, passkeyVerified, stillOwner, updateItem, vaultName, verifyMasterPassword } from "./vault";

/** The confirmation window has closed by the time the passkey is saved: the storage limit is said inside the page (PassAuth's own words, no vault data). */
const QUOTA_NOTE = pageText`PassAuth couldn't save the passkey. You've reached this server's storage limit. Delete items or ask the server's admin.`;
/** The same when the server is running out of disk space (507 `insufficient_storage`). */
const STORAGE_NOTE = pageText`PassAuth couldn't save the passkey. Your server is running out of storage space. Ask the server's admin.`;

/**
 * `credentialId`: for sign-in the chosen passkey; for creation the login to save it in (an item id, or `NEW_LOGIN`).
 * `verified`: the user was verified (the UV flag): master password entered now or recently enough.
 */
type Decision = {
  accept: boolean;
  credentialId?: string;
  fallback?: boolean;
  verified: boolean;
  /**
   * Why a request wasn't accepted: the user cancelled (or closed the window), it timed out, the page aborted it, or
   * the page went away (navigated, reloaded, closed; another document's request replaced it). The first three hold
   * the tab back (`backedOff`).
   */
  why?: "user" | "timeout" | "page" | "gone";
};

type Reply = PasskeyRuntimeReply;

export interface PasskeyMessage {
  type: "passkey:create" | "passkey:get";
  /** As the page sent them (checked by passkeys.ts before anything is created or signed). */
  options: CreateRequest | GetRequest;
  origin: string;
  topLevel: boolean;
  tabId: number;
  frameId: number;
  /** The page bridge's request id, so an abort on the page can cancel the confirmation. */
  bridgeId: string;
  /** The requesting document (`sender.documentId`): a request from a page that has gone since doesn't block its tab. */
  documentId?: string;
  /** The page had transient user activation when it asked (a click or key press just before). */
  activated: boolean;
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
  /** Creation: the choice preselected under "Save in" (a candidate's id, or `NEW_LOGIN`). */
  selected?: string;
  /** What the site asked for about user verification. */
  uv: UserVerification;
  /** The window asks for the master password: the site requires user verification and it wasn't entered recently. */
  needsPassword: boolean;
  /** The page had a user gesture when it asked. */
  activated: boolean;
  tabId: number;
  frameId: number;
  bridgeId: string;
  documentId?: string;
  decide: (d: Decision) => void;
}

// Same bounds as the page shim (page/webauthn.ts), so the window never outlives the page's own timeout.
// At most 4 minutes: the request belongs to the account that was unlocked when it came in.
const DEFAULT_TIMEOUT_MS = 120_000;
const MIN_TIMEOUT_MS = 10_000;
export const MAX_TIMEOUT_MS = 240_000;

const pending = new Map<string, Pending>();
const FALLBACK = { fallback: true } as const;
const notAllowed = (message = "The request was cancelled.") => ({ error: { name: "NotAllowedError", message } });

/** The first hold after a cancel, and the longest (each further cancel doubles it). */
export const BACKOFF_MS = 30_000;
export const MAX_BACKOFF_MS = 10 * 60_000;
/** Per tab: how many cancels in a row, and until when requests without a user gesture are refused. */
const holds = new Map<number, { strikes: number; until: number }>();

/** A request in `tabId` ended without the user's yes (see the file comment): the tab is held back, longer each time. */
function holdBack(tabId: number, now = Date.now()) {
  const h = holds.get(tabId);
  // Cancels long after the last hold ended start again from the first step.
  const strikes = h && now - h.until < MAX_BACKOFF_MS ? h.strikes + 1 : 1;
  holds.set(tabId, { strikes, until: now + Math.min(BACKOFF_MS * 2 ** (strikes - 1), MAX_BACKOFF_MS) });
}

/** Whether requests without a user gesture from `tabId` are refused right now. */
export function backedOff(tabId: number, now = Date.now()): boolean {
  const h = holds.get(tabId);
  return !!h && now < h.until;
}

/** How a request ended, for the tab's hold: a yes (or handing it to the browser) clears it; a cancel adds to it. */
function noteOutcome(tabId: number, d: Decision) {
  if (d.accept) holds.delete(tabId);
  else if (!d.fallback && (d.why === "user" || d.why === "timeout" || d.why === "page")) holdBack(tabId);
}

/** The confirmation window waits for the page's own timeout, within 10 s … 4 min. */
export function timeoutOf(options: unknown): number {
  const timeout = (options as { timeout?: unknown } | null | undefined)?.timeout;
  const t = typeof timeout === "number" && Number.isFinite(timeout) ? timeout : DEFAULT_TIMEOUT_MS;
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, t));
}

export async function handlePasskey(msg: PasskeyMessage): Promise<Reply> {
  // The user just cancelled in this tab (or the page aborted): no window again without a fresh click or key press.
  if (!msg.activated && backedOff(msg.tabId)) return notAllowed();
  // The server's key page in PassAuth's security-key window (two-step-key.ts; top-level frame, key page origin): the
  // account signing in there is never unlocked, so the browser's own security key / passkey UI answers.
  if (await isKeyPageRequest(msg)) return FALLBACK;
  // The RP ID rules and "Save in" targets are the core's.
  await initCore();
  // Before the user has seen anything, any problem (locked, server down, odd
  // request) hands the request to the browser's own authenticators.
  if (!msg.topLevel || !(await ensureUnlocked().catch(loggedAs(false, "Opening the vault for a passkey")))) return FALLBACK;
  // One confirmation window per tab: a page can't stack windows or steal focus repeatedly. A request left behind by a
  // page that has gone since (the tab reloaded or navigated) is closed instead of blocking the tab until it times out.
  for (const p of [...pending.values()].filter((x) => x.tabId === msg.tabId)) {
    if (p.documentId && msg.documentId && p.documentId !== msg.documentId) p.decide({ accept: false, verified: false, why: "gone" });
    else return notAllowed("Another passkey request is already open in this tab.");
  }
  try {
    return await handle(msg);
  } catch (e) {
    if (!(e instanceof PasskeyError)) log.debug("A passkey request failed:", e);
    return errorReply(e);
  }
}

/** Locked, signed out or switched accounts while the window was open: nothing is written or signed for the new state. */
const CHANGED = "PassAuth was locked or switched accounts while you decided. Try again on the website.";

async function handle(msg: PasskeyMessage): Promise<Reply> {
  let rpId: string;
  try {
    // Whatever the page put there (effectiveRpId checks it is a string).
    const requested = msg.type === "passkey:create" ? (msg.options as Partial<CreateRequest>).rp?.id : (msg.options as Partial<GetRequest>).rpId;
    rpId = effectiveRpId(requested as string | undefined, msg.origin);
  } catch (e) {
    if (e instanceof PasskeyError) return { error: { name: e.name, message: e.message } };
    return FALLBACK;
  }
  const kind = msg.type === "passkey:create" ? "create" : "get";
  // The request belongs to the account unlocked now: re-checked after the window, before anything is signed or saved.
  const who = owner();
  const uv = userVerification(kind, msg.options);
  const needsPassword = uv === "required" && !(await passkeyVerified());
  const base = { origin: msg.origin, rpId, uv, needsPassword, tabId: msg.tabId, frameId: msg.frameId, bridgeId: msg.bridgeId, documentId: msg.documentId, activated: msg.activated };
  const wait = timeoutOf(msg.options);

  if (kind === "create") {
    // Page-supplied names are cut to 256 characters before they are shown or stored.
    const req = capPasskeyNames(msg.options as CreateRequest);
    if (!supportsCreateRequest(req)) return FALLBACK;
    const host = new URL(msg.origin).hostname.toLowerCase();
    const targets = saveTargets(host, rpId, req.user?.name ?? "", req.user?.displayName ?? "");
    const candidates = targets.map((t) => ({
      credentialId: t.id,
      userName: clip(t.username),
      itemName: clip(t.name || host),
      preferred: t.preferred,
      vault: t.vault && clip(t.vault, 40),
    }));
    // Preselected: the user's own login for this exact host, else a new login (the core's choice).
    const decision = await confirm({ ...base, kind, userName: clip(req.user?.name ?? ""), candidates, selected: passkeyDefaultTarget(targets) }, wait);
    if (!decision.accept) return decision.fallback ? FALLBACK : notAllowed();
    if (!stillOwner(who)) return notAllowed(CHANGED);
    // Checked after the user's consent so a site can't silently probe the vault.
    if (
      excludedPasskeyExists(
        req,
        msg.origin,
        allPasskeys().map((x) => x.passkey),
      )
    ) {
      return { error: { name: "InvalidStateError", message: "A passkey for this account is already saved in PassAuth." } };
    }
    const { passkey, response } = await createPasskey(req, msg.origin, { uv: decision.verified });
    if (!stillOwner(who)) return notAllowed(CHANGED);
    try {
      await storePasskey(passkey, host, decision.credentialId ?? NEW_LOGIN);
    } catch (e) {
      const note = codeOf(e) === QUOTA_EXCEEDED ? QUOTA_NOTE : codeOf(e) === INSUFFICIENT_STORAGE ? STORAGE_NOTE : null;
      if (note) await notifyTab(msg.tabId, note).catch(logged("Showing a note in the page"));
      throw e;
    }
    return { result: response };
  }

  const req = msg.options as GetRequest;
  const all = allPasskeys();
  let matches: Passkey[];
  try {
    matches = matchingPasskeys(
      req,
      msg.origin,
      all.map((x) => x.passkey),
    );
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
  // The keys in `matches` were read before the window opened: after a lock they must not sign anything.
  if (!stillOwner(who)) return notAllowed(CHANGED);
  const chosen = matches.find((p) => p.credential_id === decision.credentialId) ?? matches[0];
  if (!chosen) return FALLBACK;
  const { response } = await getAssertion(req, msg.origin, chosen, { uv: decision.verified });
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

/** The logins a new passkey can be saved in, best first (the core's rule: site.ts `passkeySaveTargets`). */
function saveTargets(host: string, rpId: string, userName: string, displayName: string): PasskeyTarget[] {
  const logins = allEntries()
    .filter((e) => e.item.login)
    .map((e) => ({
      id: e.id,
      name: e.item.name,
      username: e.item.login!.username,
      urls: e.item.login!.urls.map((u) => u.url).filter((u): u is string => typeof u === "string"),
      writable: canWrite(e),
      personal: isPersonal(e),
      vault: vaultName(e.vaultId),
    }));
  return passkeySaveTargets(logins, host, rpId, userName, displayName);
}

/**
 * Save the passkey in the login the user chose (still one they can edit for this site), or in a new login in
 * their own vault, named after the site's host (never the page-supplied `rp.name`).
 */
async function storePasskey(passkey: Passkey, host: string, targetId: string) {
  // Only a login that is (still) one of the choices for this site; anything else becomes a new login in the user's own vault.
  const target = targetId !== NEW_LOGIN && saveTargets(host, passkey.rp_id, "", "").some((t) => t.id === targetId) ? getEntry(targetId) : undefined;
  if (target?.item.login) {
    const login = target.item.login!;
    await updateItem(target, { ...target.item, login: { ...login, passkeys: [...login.passkeys, passkey] } });
    return;
  }
  const now = Math.floor(Date.now() / 1000);
  const item: Item = {
    name: host.replace(/^www\./, "") || passkey.rp_id,
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
    const timer = setTimeout(() => finish({ accept: false, verified: false, why: "timeout" }), timeoutMs);
    // The user closed the window: a cancel.
    const onRemoved = (windowId: number) => windowId === winId && finish({ accept: false, verified: false, why: "user" });
    finish = (d: Decision) => {
      if (!pending.has(id)) return;
      clearTimeout(timer);
      chrome.windows.onRemoved.removeListener(onRemoved);
      pending.delete(id);
      noteOutcome(p.tabId, d);
      // Closed by the user already, or never opened: nothing to close.
      if (winId !== undefined) chrome.windows.remove(winId).catch(() => {});
      resolve(d);
    };
    chrome.windows.onRemoved.addListener(onRemoved);
    pending.set(id, { ...p, decide: (d) => finish(d) });
    // Centred over the browser window that holds the requesting tab (and so on that window's display).
    openCentered(chrome.runtime.getURL(`popup.html#passkey=${id}`), sheetSize(p), { tabId: p.tabId }).then(
      (win) => {
        winId = win?.id;
        if (!pending.has(id) && winId !== undefined) chrome.windows.remove(winId).catch(() => {}); // see above
      },
      () => finish({ accept: false, verified: false, why: "gone" }),
    );
  });
  return result;
}

export async function pendingRequest(id: string): Promise<PasskeyRequestInfo | null> {
  const p = pending.get(id);
  if (!p) return null;
  const { decide: _decide, tabId: _t, frameId: _f, bridgeId: _b, documentId: _d, uv: _uv, activated: _a, ...info } = p;
  // The site icon comes from the user's server, which fetches it from the site. Only for a site the vault
  // already has a login for: before the user has agreed to anything, a page must not be able to make
  // the server fetch an icon for whatever host it names.
  const { server, settings } = await local.get();
  return { ...info, server, showIcons: (p.kind === "get" || p.candidates.length > 0) && (await iconsShown(server, settings.showIcons)) };
}

/**
 * The user's answer in the window. User verification is worked out here, at the
 * moment of the decision: the master password typed in the window (checked
 * locally against the account's keys), or an entry recent enough. When the site
 * requires it and neither holds (the few minutes ran out while the window was
 * open), the window is asked to show the password field.
 */
export async function decide(id: string, accept: boolean, credentialId?: string, fallback?: boolean, password?: string) {
  const p = pending.get(id);
  if (!p) throw new AppError(EXPIRED, "This request has expired. Try again on the website.");
  let verified = false;
  if (accept && p.uv !== "discouraged") {
    if (p.needsPassword && password) {
      await verifyMasterPassword(password);
      verified = true;
    } else verified = await passkeyVerified();
    if (p.uv === "required" && !verified) {
      p.needsPassword = true;
      throw new AppError(PASSWORD_REQUIRED, "Enter your master password to continue.");
    }
  }
  p.decide({ accept, credentialId, fallback, verified, ...(accept ? {} : { why: "user" as const }) });
}

/**
 * The page aborted or timed out its request (`gone`: the page itself went away): close the window without creating
 * or using anything. An abort holds the tab back like a cancel (a page can't open, abort and reopen the window in a
 * loop); a page that went away doesn't.
 */
export function cancelPasskey(tabId: number, frameId: number, bridgeId: string, gone = false) {
  for (const p of pending.values()) if (p.tabId === tabId && p.frameId === frameId && p.bridgeId === bridgeId) p.decide({ accept: false, verified: false, why: gone ? "gone" : "page" });
}

/** The tab closed: its requests' windows close too (nobody is waiting for them), and its hold goes. */
export function cancelPasskeysInTab(tabId: number) {
  for (const p of [...pending.values()]) if (p.tabId === tabId) p.decide({ accept: false, verified: false, why: "gone" });
  holds.delete(tabId);
}
