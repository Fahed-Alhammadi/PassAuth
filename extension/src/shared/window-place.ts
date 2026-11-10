/**
 * Where PassAuth's own windows (passkey confirmation, unlock, pop-out) open
 * and how big they are. Pure maths, unit-tested in test/window-place.test.mjs;
 * the chrome.windows calls are in windows.ts.
 *
 * All values are screen coordinates in DIPs, as chrome.windows reports them.
 * Displays left of or above the primary one have negative coordinates, so
 * nothing here assumes 0,0 is a corner of the screen.
 */

export interface Size {
  width: number;
  height: number;
}

export interface Bounds extends Size {
  left: number;
  top: number;
}

/** What the OS adds around the page: title bar and borders (outer size − inner size). */
export type Frame = Size;

/** First guess per OS (`chrome.runtime.PlatformInfo.os`) until a window has measured its own frame. */
const DEFAULT_FRAMES: Record<string, Frame> = {
  mac: { width: 0, height: 28 },
  win: { width: 16, height: 39 },
  linux: { width: 0, height: 37 },
  cros: { width: 0, height: 32 },
};

export const defaultFrame = (os: string): Frame => DEFAULT_FRAMES[os] ?? DEFAULT_FRAMES.linux;

/** A measured frame is believable: no page zoom or odd window state distorted it. */
export function plausibleFrame(f: Partial<Frame> | null | undefined): f is Frame {
  return !!f && Number.isFinite(f.width) && Number.isFinite(f.height) && f.width! >= 0 && f.width! <= 64 && f.height! >= 0 && f.height! <= 160;
}

/** The window size that gives the page exactly `content`. */
export const outerSize = (content: Size, frame: Frame): Size => ({ width: Math.round(content.width + frame.width), height: Math.round(content.height + frame.height) });

/** Bounds of a window that can be used as an anchor (not minimised, real numbers), else null. */
export function usableBounds(w: (Partial<Bounds> & { state?: string }) | null | undefined): Bounds | null {
  if (!w || w.state === "minimized") return null;
  const { left, top, width, height } = w;
  if (![left, top, width, height].every((n) => typeof n === "number" && Number.isFinite(n))) return null;
  return width! > 0 && height! > 0 ? { left: left!, top: top!, width: width!, height: height! } : null;
}

/**
 * Centre a window of `size` over `anchor` (the browser window the request came
 * from). On an axis where it is larger than the anchor it lines up with the
 * anchor's left/top edge instead, so its title bar stays where the anchor's is.
 */
export function centerOver(anchor: Bounds, size: Size): Bounds {
  const along = (start: number, room: number, need: number) => Math.round(need <= room ? start + (room - need) / 2 : start);
  return { left: along(anchor.left, anchor.width, size.width), top: along(anchor.top, anchor.height, size.height), width: size.width, height: size.height };
}

/** Keep `b` completely inside `area` (a display's work area); a window larger than the area is shrunk to it. */
export function clampTo(b: Bounds, area: Bounds): Bounds {
  const width = Math.min(b.width, area.width);
  const height = Math.min(b.height, area.height);
  const within = (v: number, min: number, max: number) => Math.round(Math.min(Math.max(v, min), max));
  return { left: within(b.left, area.left, area.left + area.width - width), top: within(b.top, area.top, area.top + area.height - height), width, height };
}

/**
 * Give the window at `current` the new `size` around the same centre (a size
 * correction then doesn't read as a move), kept inside `area` when it is known.
 */
export function resizeCentered(current: Bounds, size: Size, area?: Bounds | null): Bounds {
  const next = {
    left: Math.round(current.left + (current.width - size.width) / 2),
    top: Math.round(current.top + (current.height - size.height) / 2),
    width: size.width,
    height: size.height,
  };
  return area ? clampTo(next, area) : next;
}

/** Same bounds within a pixel: no update needed. */
export const sameBounds = (a: Bounds, b: Bounds) => Math.abs(a.left - b.left) <= 1 && Math.abs(a.top - b.top) <= 1 && Math.abs(a.width - b.width) <= 1 && Math.abs(a.height - b.height) <= 1;
