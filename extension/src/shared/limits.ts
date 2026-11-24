/**
 * Length caps on strings a web page hands to PassAuth (typed credentials,
 * passkey names). Applied in the content script and again in the background,
 * which never trusts the page side. Unit-tested in test/limits.test.ts.
 */

/** Longest user name PassAuth offers to save (characters). */
export const MAX_USERNAME = 1024;
/** Longest password PassAuth offers to save (characters). */
export const MAX_PASSWORD = 4096;
/** Longest relying-party or user name stored with a passkey (characters; WebAuthn lets authenticators truncate them). */
export const MAX_PASSKEY_NAME = 256;

/** Typed credentials worth offering to save: a password, and neither value longer than its cap (a cut-off secret would be wrong). */
export function credentialsFit(username: unknown, password: unknown): boolean {
  return typeof username === "string" && typeof password === "string" && !!password && username.length <= MAX_USERNAME && password.length <= MAX_PASSWORD;
}

/** Cut a page-supplied name to `max` characters (whole code points). */
export function capName(value: string, max = MAX_PASSKEY_NAME): string {
  if (value.length <= max) return value;
  return [...value].slice(0, max).join("");
}

type Named = { name?: unknown; displayName?: unknown };

/** A copy of WebAuthn creation options with `rp.name`, `user.name` and `user.displayName` cut to MAX_PASSKEY_NAME; anything else unchanged. */
export function capPasskeyNames<T>(options: T): T {
  if (!options || typeof options !== "object") return options;
  const o = options as { rp?: Named; user?: Named };
  const cap = (x: Named | undefined, keys: ("name" | "displayName")[]) => {
    if (!x || typeof x !== "object") return x;
    const out: Named = { ...x };
    for (const k of keys) if (typeof out[k] === "string") out[k] = capName(out[k] as string);
    return out;
  };
  return { ...options, ...(o.rp !== undefined ? { rp: cap(o.rp, ["name"]) } : {}), ...(o.user !== undefined ? { user: cap(o.user, ["name", "displayName"]) } : {}) } as T;
}

/** Sign-in with this many passkeys for one site or more: the passkey window gets a search field over them. */
export const PASSKEY_SEARCH_FROM = 4;
