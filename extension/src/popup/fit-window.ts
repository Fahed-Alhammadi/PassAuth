/**
 * The page side of PassAuth's own windows (shared/windows.ts opens them): make
 * the window's page area exactly the size of its content. Needs the DOM
 * (window size, screen), so only PassAuth's pages use it.
 */

import { type Keep, plausibleFrame, resizeFrom, type Size, sameBounds, usableBounds } from "../shared/window-place";
import { FRAME_KEY, storedFrame } from "../shared/windows";

let fitting: Promise<void> = Promise.resolve();
let frameNoted = false;

/**
 * Called by the window's own page once its content is laid out (and again when
 * the content changes size): make the page area exactly `content()`. The
 * window opened with a guess for the OS frame and the content height; this
 * corrects it around the same centre (or the same top-right corner), inside the display's work area.
 * Calls run one after another, each measuring the content when its turn comes.
 */
export function fitWindow(content: () => Size, keep: Keep = "center"): Promise<void> {
  fitting = fitting.then(
    () => fitOnce(content, keep),
    () => fitOnce(content, keep),
  );
  return fitting;
}

async function fitOnce(content: () => Size, keep: Keep): Promise<void> {
  // Page zoom scales the page's own pixels against the window's (unknown: assume none).
  const zoom = await (chrome.tabs.getZoom?.() ?? Promise.resolve(1)).catch(() => 1);
  // A resize reaches the page a moment after the window: check again until both agree (a few rounds at most).
  for (let round = 0; round < 3; round++) {
    const win = await chrome.windows?.getCurrent().catch(() => null);
    const current = usableBounds(win);
    // Only PassAuth's own windows; never the browser window a toolbar popup belongs to.
    if (!win?.id || win.type !== "popup" || win.state !== "normal" || !current) return;
    if (!frameNoted) {
      // Before anything was resized, window size − page size is the OS frame: remember it for the next window.
      frameNoted = true;
      const measured = { width: current.width - innerWidth, height: current.height - innerHeight };
      const stored = await storedFrame();
      if (zoom === 1 && plausibleFrame(measured) && (stored?.width !== measured.width || stored?.height !== measured.height)) {
        // Only a better first guess for the next window: nothing is lost if it isn't kept.
        void chrome.storage.local.set({ [FRAME_KEY]: measured }).catch(() => {});
      }
    }
    const want = content();
    const size = { width: Math.round(current.width + (want.width - innerWidth) * zoom), height: Math.round(current.height + (want.height - innerHeight) * zoom) };
    const s = screen as Screen & { availLeft?: number; availTop?: number };
    const area = usableBounds({ left: s.availLeft ?? 0, top: s.availTop ?? 0, width: s.availWidth, height: s.availHeight });
    const next = resizeFrom(current, size, keep, area);
    if (sameBounds(current, next)) return;
    const resized = next.width === current.width && next.height === current.height;
    const settled = resized
      ? Promise.resolve()
      : new Promise<void>((done) => {
          addEventListener("resize", () => done(), { once: true });
          setTimeout(done, 400);
        });
    // The window was closed or can't be resized right now: it keeps its size.
    await chrome.windows.update(win.id, next).catch(() => {});
    await settled;
  }
}
