/**
 * Size of the inline autofill menu frame. It is the same whatever the menu shows (locked, no logins, one login or
 * many, an error): the page can measure the frame's host element, so its size must not tell it whether PassAuth is
 * locked or how many logins it has for the site. The list scrolls inside, and messages wrap inside the same box
 * (inline/main.ts, inline.css).
 */
export const INLINE_MENU = {
  /** Brand line with "⋯" at the top. */
  head: 36,
  row: 52,
  /** Padding around the rows, top and bottom together. */
  listPad: 8,
  /** Rows that fit; half of the next one peeks out to say there is more. */
  rows: 2.5,
  /** The footer ("New login", "Use a strong password"). */
  foot: 44,
  /** Top and bottom border together. */
  border: 2,
} as const;

/** The menu frame's one height. */
export const INLINE_MENU_HEIGHT = INLINE_MENU.border + INLINE_MENU.head + INLINE_MENU.listPad + INLINE_MENU.rows * INLINE_MENU.row + INLINE_MENU.foot;
