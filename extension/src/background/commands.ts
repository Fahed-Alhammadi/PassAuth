/**
 * PassAuth from outside its own pages: the keyboard commands (fill, generate a password, lock), what the right-click
 * menu and the commands share (copy a strong password, a fill that waits for an unlock, the "copied" note), and
 * opening PassAuth. main.ts registers the listeners; menus.ts is the right-click menu.
 *
 *   autofill            fill the login used last for the page; pressed again within CYCLE_MS on the same tab, the next one
 *   generate_password   a password with the generator's saved options, copied (cleared after the user's delay)
 *   lock                lock every account
 */
import { generatorRequest } from "@web/lib/generator";
import { codeOf, NOT_FOR_SITE, pageMessage } from "../shared/errors";
import { readGeneratorSettings } from "../shared/generator-settings";
import { log, logged } from "../shared/log";
import { type PageSafeText, pageText } from "../shared/page-text";
import type { AfterUnlock } from "../shared/types";
import { openCentered, POPUP_WINDOW } from "../shared/windows";
import { touch } from "./activity";
import { copy } from "./clipboard";
import { initCore } from "./core";
import { fill, fillItem } from "./fill";
import { noteFillProblem } from "./fill-problems";
import { byLastUsed, lastUsedMap } from "./last-used";
import { matching } from "./matching";
import { baseDomain, parse } from "./site";
import { activeId, getSettings, local, scratch } from "./storage";
import { notifyTab } from "./toast";
import * as vault from "./vault";

/** Pressing the fill shortcut again within this time on the same page fills the next matching login. */
export const CYCLE_MS = 5_000;
/** A fill asked for while PassAuth was locked is done after an unlock within this time. */
export const PENDING_MS = 2 * 60_000;

const CYCLE_KEY = "fillCycle";
const PENDING_KEY = "fillAfterUnlock";

/** Open PassAuth: the toolbar popup, or without a toolbar to open from (e.g. no focused browser window) a window over the browser window. */
export async function openPopup() {
  try {
    await chrome.action.openPopup();
  } catch {
    // No toolbar to open the popup from: PassAuth in its own window instead.
    await openCentered(chrome.runtime.getURL("popup.html?popout=1"), POPUP_WINDOW);
  }
}

/** Run one keyboard command (`onCommand` is the listener). */
export async function runCommand(command: string, tab?: chrome.tabs.Tab): Promise<void> {
  await initCore();
  if (command === "autofill") await fillShortcut(tab);
  else if (command === "generate_password") await generateShortcut(tab);
  else if (command === "lock") await vault.lockAll();
}

export function onCommand(command: string, tab?: chrome.tabs.Tab) {
  void runCommand(command, tab).catch((e: unknown) => log.warn(`The ${command} shortcut failed:`, e));
}

// ------------------------------------------------------------ what is shown inside the page

const LABELS = {
  password: pageText`Password`,
  username: pageText`User name`,
  totp: pageText`Verification code`,
  generated: pageText`Strong password`,
  passphrase: pageText`Passphrase`,
} as const;

/** "1 minute", "30 seconds": the clipboard delay in words (a setting, never vault data). */
export function clearsIn(seconds: number): PageSafeText {
  if (seconds < 60) return pageText`${seconds} seconds`;
  return seconds === 60 ? pageText`1 minute` : pageText`${Math.round(seconds / 60)} minutes`;
}

/** "Password copied. It clears in 30 seconds." — what was copied is named, never the value. */
export function copiedText(what: keyof typeof LABELS, clearAfter: number): PageSafeText {
  return clearAfter > 0 ? pageText`${LABELS[what]} copied. It clears in ${clearsIn(clearAfter)}.` : pageText`${LABELS[what]} copied.`;
}

/** A failure explained inside the page: only page-safe messages (never one naming a login's websites). */
export function failureText(e: unknown, fallback: PageSafeText): PageSafeText {
  return codeOf(e) === NOT_FOR_SITE ? pageText`This login isn't saved for this site. Open PassAuth to check its websites.` : pageMessage(e, fallback);
}

// --------------------------------------------------------------------- generator

/** Generate with the saved options, copy it (cleared after the user's delay) and say so in the tab's page. */
export async function copyStrongPassword(tabId?: number) {
  const req = generatorRequest(await readGeneratorSettings());
  const value = await vault.generate(req.mode, { ...req.options });
  await copy(value);
  const { clearClipboard } = await getSettings();
  if (tabId !== undefined) await notifyTab(tabId, copiedText(req.mode === "passphrase" ? "passphrase" : "generated", clearClipboard));
}

async function activeTab(tab?: chrome.tabs.Tab) {
  return tab?.id !== undefined ? tab : (await chrome.tabs.query({ active: true, lastFocusedWindow: true }))[0];
}

async function generateShortcut(tab?: chrome.tabs.Tab) {
  const t = await activeTab(tab);
  await copyStrongPassword(t?.url?.startsWith("http") ? t.id : undefined);
}

// --------------------------------------------------------------------- filling

/** The logins for `url`, the one used last first (the vault must be open). */
export async function orderedMatches(url: string): Promise<vault.Entry[]> {
  return byLastUsed(await matching(url), await lastUsedMap(await activeId()));
}

/** What the fill shortcut remembers between presses (session storage: survives a worker restart). */
interface Cycle {
  account: string;
  tabId: number;
  url: string;
  ids: string[];
  index: number;
  at: number;
}

/** A fill asked for while PassAuth was locked: done right after an unlock (`afterUnlock`). */
interface PendingFill {
  /**
   * "menu": "Unlock to fill…" (one login → fill it, several → the popup shows them), or an entry of a menu built
   * before PassAuth locked (`itemId`: that login, card or identity); "shortcut": the login used last.
   */
  kind: "menu" | "shortcut";
  /** The item the right-click menu's entry named. */
  itemId?: string;
  account: string;
  tabId: number;
  /** The page's address when it was asked: a tab that went elsewhere since gets nothing. */
  pageUrl: string;
  /** The right-clicked frame (menu only). */
  frameId: number;
  frameUrl: string;
  at: number;
}

/** Remember a fill until the next unlock, and open PassAuth to unlock. */
export async function fillAfterUnlock(p: Omit<PendingFill, "account" | "at">) {
  await scratch.set(PENDING_KEY, { ...p, account: await activeId(), at: Date.now() } satisfies PendingFill);
  await openPopup();
}

/** The fill shortcut: the login used last for the page, the next one on another press within CYCLE_MS. */
async function fillShortcut(given?: chrome.tabs.Tab) {
  const tab = await activeTab(given);
  if (tab?.id === undefined || !tab.url?.startsWith("http")) return;
  const tabId = tab.id;
  const { tokens } = await local.get();
  if (!tokens) return void (await openPopup());
  try {
    if (!(await vault.ensureUnlocked())) return void (await fillAfterUnlock({ kind: "shortcut", tabId, pageUrl: tab.url, frameId: 0, frameUrl: tab.url }));
    await touch();
    const account = await activeId();
    const prev = await scratch.get<Cycle>(CYCLE_KEY);
    const now = Date.now();
    let cycle: Cycle;
    if (prev && prev.account === account && prev.tabId === tabId && prev.url === tab.url && now - prev.at < CYCLE_MS && now >= prev.at && prev.ids.length) {
      // The order of the first press is kept, so filling (which marks the login as used) doesn't reshuffle it.
      cycle = { ...prev, index: (prev.index + 1) % prev.ids.length, at: now };
    } else {
      const ids = (await orderedMatches(tab.url)).filter((e) => e.item.login?.password || e.item.login?.username).map((e) => e.id);
      if (!ids.length) return void (await openPopup());
      cycle = { account, tabId, url: tab.url, ids, index: 0, at: now };
    }
    await scratch.set(CYCLE_KEY, cycle);
    await fill(cycle.ids[cycle.index]!, tabId);
  } catch (e) {
    log.debug("Filling from the shortcut failed:", e);
    await noteFillProblem(tabId, e).catch(logged("Keeping the fill problem"));
    await notifyTab(tabId, failureText(e, pageText`PassAuth couldn't fill this page.`));
  }
}

/**
 * Right after an unlock (the popup asks): a fill that waited for it, if it was asked for in the last PENDING_MS, for
 * the account that is unlocked now, and the tab still shows the same page. The menu's fill goes ahead with exactly
 * one login for the page (several: the popup shows them); the shortcut's fills the login used last.
 */
export async function afterUnlock(): Promise<AfterUnlock> {
  const p = await scratch.get<PendingFill>(PENDING_KEY);
  if (!p) return { filled: false };
  await scratch.remove(PENDING_KEY);
  const now = Date.now();
  if (now - p.at > PENDING_MS || now < p.at || p.account !== (await activeId())) return { filled: false };
  const tab = await chrome.tabs.get(p.tabId).catch(() => null);
  if (!tab?.url || tab.url !== p.pageUrl) return { filled: false };
  const page = parse(tab.url);
  if (!page) return { filled: false };
  if (p.itemId) {
    // The entry the right-click menu showed: that item, checked again by fill.ts against the page and the frame.
    const { hiddenSites } = await local.get();
    if (!vault.getEntry(p.itemId) || hiddenSites.includes(baseDomain(page.hostname))) return { filled: false };
    await touch();
    if (vault.getEntry(p.itemId)?.item.login) await fill(p.itemId, p.tabId, { frameId: p.frameId, url: p.frameUrl });
    else await fillItem(p.itemId, p.tabId, p.frameId);
    return { filled: true };
  }
  const matches = (await orderedMatches(tab.url)).filter((e) => e.item.login?.password || e.item.login?.username);
  if (p.kind === "menu") {
    const { hiddenSites } = await local.get();
    if (matches.length !== 1 || hiddenSites.includes(baseDomain(page.hostname))) return { filled: false };
  }
  const first = matches[0];
  if (!first) return { filled: false };
  await touch();
  await fill(first.id, p.tabId, p.kind === "menu" ? { frameId: p.frameId, url: p.frameUrl } : undefined);
  return { filled: true };
}
