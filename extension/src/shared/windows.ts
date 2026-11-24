/**
 * PassAuth's own windows (passkey confirmation, unlock, pop-out): opened
 * centred over the browser window they belong to (the passkey window: at its
 * top right, under the toolbar), sized to their content.
 * Opening works in the service worker; the window's page then fits itself to
 * its content (popup/fit-window.ts). The maths is in window-place.ts.
 */
import { type Bounds, centerOver, defaultFrame, type Frame, outerSize, plausibleFrame, type Size, underToolbar, usableBounds } from "./window-place";

/** The measured frame of a PassAuth window, remembered so the next one opens at its final size. */
export const FRAME_KEY = "windowFrame";

/** Page size of the popup when it runs in its own window (pop-out, unlock). */
export const POPUP_WINDOW: Size = { width: 400, height: 620 };

/** The frame a PassAuth window measured last time, if it looks like a real one. */
export async function storedFrame(): Promise<Frame | undefined> {
  // Unreadable storage: open with the first guess instead.
  const got: Record<string, unknown> = await chrome.storage.local.get(FRAME_KEY).catch(() => ({}));
  const f = got[FRAME_KEY] as Partial<Frame> | undefined;
  return plausibleFrame(f) ? f : undefined;
}

async function frame(): Promise<Frame> {
  const stored = await storedFrame();
  if (stored) return stored;
  const os = await chrome.runtime.getPlatformInfo().then(
    (p) => p.os,
    () => "",
  );
  return defaultFrame(os);
}

/** The browser window to open over: the given window, the tab's window, else the last focused browser window. */
async function anchor(from: { windowId?: number; tabId?: number }): Promise<Bounds | null> {
  let windowId = from.windowId;
  // A tab or window that is gone by now: fall back to the last focused browser window.
  if (windowId === undefined && from.tabId !== undefined)
    windowId = await chrome.tabs.get(from.tabId).then(
      (t) => t.windowId,
      () => undefined,
    );
  const own = windowId === undefined ? null : usableBounds(await chrome.windows.get(windowId).catch(() => null));
  return own ?? usableBounds(await chrome.windows.getLastFocused({ windowTypes: ["normal"] }).catch(() => null));
}

/**
 * Open a PassAuth window whose page area is `content`, centred over the
 * browser window of `from` (so it also lands on that window's display).
 */
export function openCentered(url: string, content: Size, from: { windowId?: number; tabId?: number } = {}): Promise<chrome.windows.Window | undefined> {
  return openWindow(url, content, from, centerOver);
}

/**
 * Open a PassAuth window whose page area is `content` at the top right of the browser window of `from`, under its
 * toolbar, where the extension's own popup appears (the passkey window): the page itself stays in view.
 */
export function openUnderToolbar(url: string, content: Size, from: { windowId?: number; tabId?: number } = {}): Promise<chrome.windows.Window | undefined> {
  return openWindow(url, content, from, underToolbar);
}

async function openWindow(url: string, content: Size, from: { windowId?: number; tabId?: number }, place: (anchor: Bounds, size: Size) => Bounds): Promise<chrome.windows.Window | undefined> {
  const size = outerSize(content, await frame());
  const over = await anchor(from);
  const base = { url, type: "popup" as const, focused: true, ...size };
  if (over) {
    const { left, top } = place(over, size);
    try {
      return await chrome.windows.create({ ...base, left, top });
    } catch {
      // Chrome refuses bounds that are mostly off-screen (a browser window dragged past the edge): let it place the window.
    }
  }
  return chrome.windows.create(base);
}
