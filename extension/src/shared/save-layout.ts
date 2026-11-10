/**
 * Size of the save prompt. The content script sizes the frame before the
 * prompt page (save/main.ts, save.css) has loaded, so the background works out
 * a first height from these numbers; the prompt then reports its real height.
 */
export const SAVE_PROMPT = {
  width: 340,
  /** Distance from the top-right corner of the page. */
  edge: 16,
} as const;

/**
 * First guess for the prompt's height (save.css): border 2, brand bar 48, body
 * padding 4 + 16, context row 40, the "Save in" card (label 28, rows of 56,
 * at most 4½ showing), a two-line note, actions 80 − 8, gaps of 16.
 */
export function promptHeight(targets: number): number {
  const rows = targets ? targets + 1 : 0;
  const list = rows ? 28 + Math.min(rows * 56 + 2, 254) + 16 : 0;
  return 2 + 48 + 4 + 40 + 16 + list + 40 + 16 + 80 - 8 + 16;
}

/** A height the content script will accept from the prompt. */
export const clampPromptHeight = (height: number): number => (Number.isFinite(height) ? Math.round(Math.min(Math.max(height, 120), 720)) : 320);
