/**
 * Size of the inline autofill menu. The content script sizes the frame before
 * the menu page (inline/main.ts, inline.css) has loaded, so both use these numbers.
 */
export const INLINE_MENU = {
  /** Brand line at the top. */
  head: 32,
  row: 52,
  /** Padding around the rows, top and bottom together. */
  listPad: 8,
  /** Top and bottom border together. */
  border: 2,
  /** Rows that show before the list scrolls; half of the next one peeks out to say there is more. */
  maxRows: 4,
  /** The "locked" message with its button. */
  locked: 96,
} as const;

export function inlineMenuHeight(locked: boolean, count: number): number {
  const m = INLINE_MENU;
  if (locked) return m.border + m.head + m.locked;
  const rows = count > m.maxRows ? m.maxRows + 0.5 : Math.max(count, 1);
  return m.border + m.head + m.listPad + rows * m.row;
}
