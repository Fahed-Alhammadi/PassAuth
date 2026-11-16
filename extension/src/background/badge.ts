/**
 * The toolbar icon: how many saved logins match each window's active tab (nothing while locked), and a locked
 * variant of the icon (grey, with a padlock; title "PassAuth is locked") so the state shows without colour alone.
 * Counted from the match index (match-index.ts) when there is one, so a worker restart doesn't decrypt the vault for
 * it. While a sign-in on another device waits for this account's approval (sign-in-requests.ts), the badge is a dot
 * in the warning colour instead of the count, and the title says why: nothing opens by itself, nothing shows in pages.
 * main.ts calls `refreshBadge` on tab, window and storage changes (`pageStateChanged`).
 */
import { log } from "../shared/log";
import { initCore } from "./core";
import { countMatching } from "./matching";
import { SIGN_IN_REQUESTS_PREFIX, signInWaiting } from "./sign-in-requests";
import { getSettings } from "./storage";
import * as vault from "./vault";

const COLOR = "#0866ED";
/** The dot for a sign-in waiting for approval: the warning colour of the apps (web `--warn`). */
const WAITING_COLOR = "#965A00";
/** A badge with a space draws as a small dot. */
const DOT = " ";
const TITLES = { locked: "PassAuth is locked", waiting: "PassAuth: a sign-in on another device is waiting for your approval", normal: "PassAuth" } as const;
const SIZES = [16, 32] as const;

/** Colours, once per worker start. */
export function initBadge() {
  void chrome.action.setBadgeBackgroundColor({ color: COLOR });
  void chrome.action.setBadgeTextColor?.({ color: "#FFFFFF" });
}

/** The locked icon, drawn once per worker from the normal one (null where there is no OffscreenCanvas). */
let lockedImages: Promise<Record<number, ImageData> | null> | null = null;

/** A padlock in the lower right corner, on a white disc so it reads on any toolbar. */
function drawLock(ctx: OffscreenCanvasRenderingContext2D, size: number) {
  const s = size / 16;
  const cx = 11.5 * s;
  const cy = 11.5 * s;
  ctx.fillStyle = "#FFFFFF";
  ctx.beginPath();
  ctx.arc(cx, cy, 4.5 * s, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = "#1F2937";
  ctx.strokeStyle = "#1F2937";
  ctx.lineWidth = 1.1 * s;
  ctx.beginPath();
  ctx.arc(cx, cy - 1 * s, 1.5 * s, Math.PI, 0);
  ctx.stroke();
  ctx.fillRect(cx - 2.4 * s, cy - 0.9 * s, 4.8 * s, 3.6 * s);
}

async function drawLocked(): Promise<Record<number, ImageData> | null> {
  if (typeof OffscreenCanvas === "undefined" || typeof createImageBitmap === "undefined") return null;
  const out: Record<number, ImageData> = {};
  for (const size of SIZES) {
    const blob = await (await fetch(chrome.runtime.getURL(`icons/icon-${size}.png`))).blob();
    const bitmap = await createImageBitmap(blob);
    const canvas = new OffscreenCanvas(size, size);
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;
    ctx.filter = "grayscale(1) opacity(0.6)";
    ctx.drawImage(bitmap, 0, 0, size, size);
    ctx.filter = "none";
    drawLock(ctx, size);
    out[size] = ctx.getImageData(0, 0, size, size);
  }
  return out;
}

/** What the icon and its title show now (unknown after a worker start: they are set once). */
let shown: "locked" | "normal" | null = null;
let titled: keyof typeof TITLES | null = null;

async function updateTitle(want: keyof typeof TITLES) {
  if (titled === want) return;
  titled = want;
  await chrome.action.setTitle({ title: TITLES[want] }).catch((e: unknown) => {
    titled = null;
    log.debug("Updating the toolbar title failed:", e);
  });
}

async function updateIcon(locked: boolean) {
  const want = locked ? "locked" : "normal";
  if (shown === want) return;
  shown = want;
  try {
    if (locked) {
      lockedImages ??= drawLocked().catch((e: unknown) => {
        log.debug("Drawing the locked icon failed:", e);
        return null;
      });
      const images = await lockedImages;
      if (images) await chrome.action.setIcon({ imageData: images });
    } else {
      await chrome.action.setIcon({ path: { 16: "icons/icon-16.png", 32: "icons/icon-32.png" } });
    }
  } catch (e) {
    shown = null;
    log.debug("Updating the toolbar icon failed:", e);
  }
}

async function updateBadge() {
  await initCore();
  const status = await vault.lockStatus();
  await updateIcon(status === "locked");
  const waiting = status === "unlocked" && (await signInWaiting());
  await updateTitle(status === "locked" ? "locked" : waiting ? "waiting" : "normal");
  const { badge } = await getSettings();
  for (const tab of await chrome.tabs.query({ active: true })) {
    if (tab.id === undefined) continue;
    const n = !waiting && badge && status === "unlocked" && tab.url?.startsWith("http") ? ((await countMatching(tab.url)) ?? 0) : 0;
    // The tab may have closed meanwhile: nothing to show then.
    await chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: waiting ? WAITING_COLOR : COLOR }).catch(() => {});
    await chrome.action.setBadgeText({ tabId: tab.id, text: waiting ? DOT : n ? String(Math.min(n, 99)) : "" }).catch(() => {});
  }
}

let timer: ReturnType<typeof setTimeout> | undefined;

/** Update the badge soon (changes come in bursts: one update for all of them). */
export function refreshBadge() {
  clearTimeout(timer);
  timer = setTimeout(() => void updateBadge().catch((e: unknown) => log.debug("Updating the badge failed:", e)), 250);
}

/** chrome.storage.local keys whose changes can change the badge, the icon or the right-click menu. */
const LOCAL_KEYS = new Set(["accounts", "active", "settings", "hiddenSites"]);

/**
 * Storage changes that can change the badge, the toolbar icon or the right-click menu: lock and unlock (session keys),
 * account switches, syncs (the match index, the account record), settings, hidden sites and which login was used last.
 * Short-lived state (prompts, heartbeats, the generator's options) doesn't.
 */
export function pageStateChanged(changes: Record<string, unknown>, area: string): boolean {
  const keys = Object.keys(changes);
  if (area === "local") return keys.some((k) => LOCAL_KEYS.has(k) || k.startsWith("lastUsed:"));
  if (area === "session") return keys.some((k) => k.startsWith("unlocked:") || k.startsWith("index:") || k.startsWith(SIGN_IN_REQUESTS_PREFIX));
  return false;
}
