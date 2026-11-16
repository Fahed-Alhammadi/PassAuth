/**
 * Sizes in plain words (storage limits and usage, the largest item a server takes) and an upper bound of an item's
 * encrypted size. Pure. Like the server, 1 KB is 1024 bytes and 1 MB is 1024 KB.
 */

const UNITS = ["KB", "MB", "GB", "TB"];

/** "1 byte", "800 bytes", "64 KB", "1.5 MB", "12 GB". */
export function formatBytes(bytes: number): string {
  const n = Number.isFinite(bytes) ? Math.max(0, bytes) : 0;
  if (n < 1024) {
    const whole = Math.round(n);
    return whole === 1 ? "1 byte" : `${whole.toLocaleString()} bytes`;
  }
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const shown = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${shown.toLocaleString()} ${UNITS[unit]}`;
}

/** Characters of unpadded base64 for `bytes` bytes. */
export const base64Length = (bytes: number): number => Math.ceil((bytes * 4) / 3);

/** What the core adds to an item's JSON when it encrypts it: a version byte, the 24-byte nonce and the 16-byte tag. */
const CIPHERTEXT_OVERHEAD = 1 + 24 + 16;
/** Room for fields the core may add to the JSON (such as `format`): the bound only ever errs towards larger. */
const JSON_SLACK = 1024;
const encoder = new TextEncoder();

/**
 * Upper bound of the length of the `data` the core makes when it encrypts `item` (unpadded base64 of the ciphertext
 * of its JSON), which the server's `max_item_kib` limits. Items above the limit by this bound are measured exactly.
 */
export function encryptedSizeBound(item: unknown): number {
  return base64Length(CIPHERTEXT_OVERHEAD + encoder.encode(JSON.stringify(item) ?? "").length + JSON_SLACK);
}
