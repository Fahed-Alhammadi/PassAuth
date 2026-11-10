/**
 * PassAuth's own windows (passkey confirmation, unlock, pop-out): opened
 * centred over the browser window they belong to, sized to their content.
 * The maths is in window-place.ts.
 */
import { centerOver, defaultFrame, outerSize, plausibleFrame, resizeCentered, sameBounds, usableBounds, type Bounds, type Frame, type Size } from "./window-place";

/** The measured frame of a PassAuth window, remembered so the next one opens at its final size. */
const FRAME_KEY = "windowFrame";

/** Page size of the popup when it runs in its own window (pop-out, unlock). */
export const POPUP_WINDOW: Size = { width: 400, height: 620 };

async function storedFrame(): Promise<Frame | undefined> {
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
  if (windowId === undefined && from.tabId !== undefined) windowId = await chrome.tabs.get(from.tabId).then((t) => t.windowId, () => undefined);
  const own = windowId === undefined ? null : usableBounds(await chrome.windows.get(windowId).catch(() => null));
  return own ?? usableBounds(await chrome.windows.getLastFocused({ windowTypes: ["normal"] }).catch(() => null));
}

/**
 * Open a PassAuth window whose page area is `content`, centred over the
 * browser window of `from` (so it also lands on that window's display).
 */
export async function openCentered(url: string, content: Size, from: { windowId?: number; tabId?: number } = {}): Promise<chrome.windows.Window | undefined> {
  const size = outerSize(content, await frame());
  const over = await anchor(from);
  const base = { url, type: "popup" as const, focused: true, ...size };
  if (over) {
    const { left, top } = centerOver(over, size);
    try {
      return await chrome.windows.create({ ...base, left, top });
    } catch {
      // Chrome refuses bounds that are mostly off-screen (a browser window dragged past the edge): let it place the window.
    }
  }
  return chrome.windows.create(base);
}

let fitting: Promise<void> = Promise.resolve();
let frameNoted = false;

/**
 * Called by the window's own page once its content is laid out (and again when
 * the content changes size): make the page area exactly `content()`. The
 * window opened with a guess for the OS frame and the content height; this
 * corrects it around the same centre, inside the display's work area.
 * Calls run one after another, each measuring the content when its turn comes.
 */
export function fitWindow(content: () => Size): Promise<void> {
  fitting = fitting.then(
    () => fit(content),
    () => fit(content),
  );
  return fitting;
}

async function fit(content: () => Size): Promise<void> {
  // Page zoom scales the page's own pixels against the window's.
  const zoom = await chrome.tabs.getZoom().catch(() => 1);
  // A resize reaches the page a moment after the window: check again until both agree (a few rounds at most).
  for (let round = 0; round < 3; round++) {
    const win = await chrome.windows.getCurrent().catch(() => null);
    const current = usableBounds(win);
    // Only PassAuth's own windows; never the browser window a toolbar popup belongs to.
    if (!win?.id || win.type !== "popup" || win.state !== "normal" || !current) return;
    if (!frameNoted) {
      // Before anything was resized, window size − page size is the OS frame: remember it for the next window.
      frameNoted = true;
      const measured = { width: current.width - innerWidth, height: current.height - innerHeight };
      const stored = await storedFrame();
      if (zoom === 1 && plausibleFrame(measured) && (stored?.width !== measured.width || stored?.height !== measured.height)) {
        void chrome.storage.local.set({ [FRAME_KEY]: measured }).catch(() => {});
      }
    }
    const want = content();
    const size = { width: Math.round(current.width + (want.width - innerWidth) * zoom), height: Math.round(current.height + (want.height - innerHeight) * zoom) };
    const s = screen as Screen & { availLeft?: number; availTop?: number };
    const area = usableBounds({ left: s.availLeft ?? 0, top: s.availTop ?? 0, width: s.availWidth, height: s.availHeight });
    const next = resizeCentered(current, size, area);
    if (sameBounds(current, next)) return;
    const resized = next.width === current.width && next.height === current.height;
    const settled = resized
      ? Promise.resolve()
      : new Promise<void>((done) => {
          addEventListener("resize", () => done(), { once: true });
          setTimeout(done, 400);
        });
    await chrome.windows.update(win.id, next).catch(() => {});
    await settled;
  }
}
