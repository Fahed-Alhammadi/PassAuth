/**
 * Text that came from elsewhere (the server, another device, another member's item), made safe to show.
 * Pure (no WASM, no network, no React) and unit-tested in `text.test.ts`.
 */

/**
 * Characters that change how text around them looks without being seen themselves: format characters (Unicode Cf:
 * bidi embeddings, overrides and isolates U+202A–E and U+2066–9, the marks U+200E/F, zero-width spaces and joiners, the
 * byte order mark U+FEFF), and the Hangul fillers that render as blanks.
 */
const FORMAT = /[\p{Cf}\u115F\u1160\u3164\uFFA0]/gu;
/** Control characters (Unicode Cc: C0, DEL, C1) and the line and paragraph separators. */
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;

/** `s` without control and format characters (for file names: nothing is put in their place). */
export function stripInvisible(s: string): string {
  return s.replace(FORMAT, "").replace(CONTROL, "");
}

/**
 * `value` as one line of plain text to show: format characters removed, control characters and line breaks turned
 * into spaces, runs of white space folded into one, trimmed, and at most `max` characters (code points), the last one
 * then an ellipsis. Anything but a string is "".
 */
export function oneLine(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const s = value.replace(FORMAT, "").replace(CONTROL, " ").replace(/\s+/g, " ").trim();
  const chars = Array.from(s);
  return chars.length <= max ? s : `${chars.slice(0, Math.max(0, max - 1)).join("").trimEnd()}…`;
}
