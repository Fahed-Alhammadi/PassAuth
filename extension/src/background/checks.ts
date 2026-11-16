/**
 * Runtime checks of requests from content scripts and framed pages (inline menu, save prompt): web pages can talk
 * to those, so nothing they send is trusted. Each `parse` in a handler table (handlers/) builds the typed request
 * from the message's fields, or returns null and the request is refused. Types and gross lengths only; the rules
 * of each feature (credential caps, nonce ownership) stay in its handler.
 */

type Fields = Record<string, unknown>;

/** Longest string field accepted at all (a typed password may be longer than what is offered for saving). */
export const MAX_FIELD = 64 * 1024;
/** Nonces and tokens PassAuth hands out (UUIDs). */
const TOKEN = /^[\w-]{8,64}$/;

export const isRecord = (v: unknown): v is Fields => typeof v === "object" && v !== null && !Array.isArray(v);

/** A string of at most `max` characters, else null. */
export const text = (v: unknown, max = MAX_FIELD): string | null => (typeof v === "string" && v.length <= max ? v : null);

/** A nonce or token PassAuth handed out, else null. */
export const token = (v: unknown): string | null => (typeof v === "string" && TOKEN.test(v) ? v : null);

/** A finite number, else null. */
export const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** One of `values`, else null. */
export const oneOf = <T extends string>(v: unknown, values: readonly T[]): T | null => (typeof v === "string" && (values as readonly string[]).includes(v) ? (v as T) : null);

/** Every field of `shape` present and valid (no null), else null. */
export function all<T extends Record<string, unknown>>(shape: { [K in keyof T]: T[K] | null }): T | null {
  for (const v of Object.values(shape)) if (v === null) return null;
  return shape as T;
}

/** A whole number from `min` to `max`, else null. */
export const whole = (v: unknown, min: number, max: number): number | null => (typeof v === "number" && Number.isInteger(v) && v >= min && v <= max ? v : null);

/** A boolean, else null. */
export const yesNo = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);

/** An optional field: undefined when it is absent, else what `check` makes of it (null: invalid). */
export const optional = <T>(v: unknown, check: (v: unknown) => T | null): T | null | undefined => (v === undefined ? undefined : check(v));

/** For requests without fields. */
export const none = (): Record<never, never> => ({});
