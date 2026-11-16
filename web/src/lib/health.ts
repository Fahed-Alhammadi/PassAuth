/**
 * Password health: weak, reused and exposed passwords among the logins the user can read.
 *
 * Pure and unit-tested (`health.test.ts`): no React, no WASM and no network of its own. Callers pass in the
 * strength estimate (the core's `estimateBits`) and `fetch`. Decrypted passwords stay in memory: reuse is found by
 * comparing them in place, and the breach check sends only the first 5 hex characters of each password's SHA-1 hash
 * to Have I Been Pwned's range API (k-anonymity, padded answers), never a full hash or a password.
 */

// ------------------------------------------------------------------ strength

/**
 * Bits, as estimated by the core's `estimateBits`, below which a password is weak ("easy to guess"). The one threshold
 * for the strength meter, the sign-up and master password checks, the generator and password health; the extension
 * and the phone apps use the same 50.
 */
export const WEAK_BITS = 50;

export type EstimateBits = (password: string) => number;

/** Weak: set, and estimated below `WEAK_BITS`. */
export function isWeak(password: string, estimateBits: EstimateBits): boolean {
  return password !== "" && estimateBits(password) < WEAK_BITS;
}

// -------------------------------------------------------------------- report

/** What the report reads from a vault entry (a `VaultEntry` fits). */
export interface HealthEntry {
  id: string;
  deletedAt: number | null;
  item: { login: { password: string } | null };
}

export interface HealthReport<T extends HealthEntry = HealthEntry> {
  /** Logins with a password that aren't in the trash: everything the report covers, in vault order. */
  logins: T[];
  /** Logins whose password is weak. */
  weak: T[];
  /** Logins that share one password, in groups of 2 or more, the largest group first. */
  reused: T[][];
  /** For each login in `reused`: how many other logins use the same password. */
  reuseCount: Map<string, number>;
}

/**
 * Weak and reused passwords among `entries` (every vault the user can read). Items in the trash, items that aren't
 * logins and logins without a password are left out. Passwords are compared as they are, in memory.
 */
export function analyze<T extends HealthEntry>(entries: readonly T[], estimateBits: EstimateBits): HealthReport<T> {
  const logins: T[] = [];
  const weak: T[] = [];
  const byPassword = new Map<string, T[]>();
  for (const e of entries) {
    const password = e.item.login?.password;
    if (e.deletedAt || !password) continue;
    logins.push(e);
    if (isWeak(password, estimateBits)) weak.push(e);
    const same = byPassword.get(password);
    if (same) same.push(e);
    else byPassword.set(password, [e]);
  }
  const reused = [...byPassword.values()].filter((group) => group.length > 1).sort((a, b) => b.length - a.length);
  const reuseCount = new Map<string, number>();
  for (const group of reused) for (const e of group) reuseCount.set(e.id, group.length - 1);
  return { logins, weak, reused, reuseCount };
}

// ------------------------------------------------------------------ breaches

/** Have I Been Pwned's Pwned Passwords API. */
export const PWNED_ORIGIN = "https://api.pwnedpasswords.com";
/** GET this + the first 5 hex characters (uppercase) of a password's SHA-1 hash. */
export const PWNED_RANGE_URL = `${PWNED_ORIGIN}/range/`;
/** Range requests running at the same time, at most. */
export const PWNED_PARALLEL = 6;
const PWNED_TIMEOUT_MS = 15_000;

/**
 * Every range request: padded answers (800 to 1,000 lines, so their size says nothing about the prefix); no cookies,
 * no Referer and no copy in the HTTP cache.
 */
export const PWNED_REQUEST: RequestInit = {
  method: "GET",
  headers: { "Add-Padding": "true" },
  credentials: "omit",
  referrerPolicy: "no-referrer",
  cache: "no-store",
};

/**
 * Why a breach check stopped. `network`: no answer at all (offline, or blocked by a Content-Security-Policy or a
 * content blocker); `invalid`: an answer that isn't a range list (e.g. a network's sign-in page); `insecure`: no
 * WebCrypto (the page isn't on https or localhost).
 */
export type BreachFailure = "network" | "timeout" | "http" | "invalid" | "insecure";

export class BreachCheckError extends Error {
  readonly reason: BreachFailure;
  /** The HTTP status, for `http`. */
  readonly status?: number;
  constructor(reason: BreachFailure, status?: number, options?: ErrorOptions) {
    super(status ? `${reason} (HTTP ${status})` : reason, options);
    this.name = "BreachCheckError";
    this.reason = reason;
    this.status = status;
  }
}

/** Uppercase hex SHA-1 of the text's UTF-8 bytes, with WebCrypto (available on https and localhost only). */
export async function sha1Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new BreachCheckError("insecure");
  const hash = new Uint8Array(await subtle.digest("SHA-1", new TextEncoder().encode(text)));
  let hex = "";
  for (const byte of hash) hex += byte.toString(16).padStart(2, "0");
  return hex.toUpperCase();
}

const RANGE_LINE = /^([0-9A-F]{35}):(\d+)$/;

/**
 * A range answer (`SUFFIX:COUNT` lines): hash suffix → times seen. Padding lines (count 0) are left out. Null when no
 * line has that shape, so a page that isn't a range answer never reads as "not found".
 */
export function parseRange(body: string): Map<string, number> | null {
  const seen = new Map<string, number>();
  let lines = 0;
  for (const line of body.split("\n")) {
    const m = RANGE_LINE.exec(line.trim().toUpperCase());
    if (!m) continue;
    lines++;
    const count = Number(m[2]);
    if (count > 0) seen.set(m[1], Math.max(count, seen.get(m[1]) ?? 0));
  }
  return lines > 0 ? seen : null;
}

export type RangeFetch = (url: string, init: RequestInit) => Promise<Response>;

export interface BreachChecker {
  /**
   * How often each distinct, non-empty password appears in known data breaches (0: not found). Passwords that share a
   * prefix share one request, answers are kept for later checks until `clear`, and at most `parallel` requests run at
   * a time (across checks). `onProgress` counts distinct passwords. The first failed request rejects the check with
   * a `BreachCheckError`; its requests that haven't started yet are then skipped.
   */
  check(passwords: Iterable<string>, onProgress?: (done: number, total: number) => void): Promise<Map<string, number>>;
  /** Stop every check in progress (each rejects with an AbortError) and forget the kept answers. */
  clear(): void;
}

export interface BreachCheckerOptions {
  /** Requests at the same time, at most (default `PWNED_PARALLEL`). */
  parallel?: number;
  /** Uppercase hex SHA-1 (default `sha1Hex`). */
  digest?: (text: string) => Promise<string>;
  /** Per request, from when it is sent until its answer has been read. */
  timeoutMs?: number;
}

const stopped = () => new DOMException("The breach check was stopped.", "AbortError");

/** Checks passwords against Have I Been Pwned through `fetchRange` (the browser's `fetch`, or a stub in tests). */
export function createBreachChecker(fetchRange: RangeFetch, options: BreachCheckerOptions = {}): BreachChecker {
  const { parallel = PWNED_PARALLEL, digest = sha1Hex, timeoutMs = PWNED_TIMEOUT_MS } = options;
  /** Answers per prefix: hash suffix → times seen. */
  let ranges = new Map<string, Map<string, number>>();
  let stop = new AbortController();
  let running = 0;
  const waiting: (() => void)[] = [];

  const acquire = (): Promise<void> => {
    if (running < parallel) {
      running++;
      return Promise.resolve();
    }
    return new Promise((resolve) => waiting.push(resolve));
  };
  // A finished request hands its slot straight to the next one, so never more than `parallel` run.
  const release = () => {
    const next = waiting.shift();
    if (next) next();
    else running--;
  };

  /** Waits for a free slot. Not sent when the checker was cleared or `run` (its check) has already failed. */
  async function request(prefix: string, signal: AbortSignal, run: { failed: boolean }): Promise<Map<string, number>> {
    await acquire();
    try {
      if (signal.aborted || run.failed) throw stopped();
      return await send(prefix, signal);
    } catch (e) {
      // Marked before the slot is handed on, so the check's next request already sees it.
      run.failed = true;
      throw e;
    } finally {
      release();
    }
  }

  async function send(prefix: string, signal: AbortSignal): Promise<Map<string, number>> {
    const ctl = new AbortController();
    const abort = () => ctl.abort();
    const timer = setTimeout(abort, timeoutMs);
    signal.addEventListener("abort", abort);
    try {
      const res = await fetchRange(PWNED_RANGE_URL + prefix, { ...PWNED_REQUEST, signal: ctl.signal });
      if (!res.ok) throw new BreachCheckError("http", res.status);
      const range = parseRange(await res.text());
      if (!range) throw new BreachCheckError("invalid");
      return range;
    } catch (e) {
      if (signal.aborted) throw stopped();
      if (e instanceof BreachCheckError) throw e;
      throw new BreachCheckError(ctl.signal.aborted ? "timeout" : "network", undefined, { cause: e });
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    }
  }

  return {
    async check(passwords, onProgress) {
      // Taken before any await: a `clear` from here on stops this check and keeps its answers out of the new cache.
      const signal = stop.signal;
      const cache = ranges;
      const distinct = [...new Set(passwords)].filter((p) => p !== "");
      const hashes = (await Promise.all(distinct.map((p) => digest(p)))).map((h) => h.toUpperCase());
      if (signal.aborted) throw stopped();
      const byPrefix = new Map<string, number[]>();
      hashes.forEach((hash, i) => {
        const prefix = hash.slice(0, 5);
        const same = byPrefix.get(prefix);
        if (same) same.push(i);
        else byPrefix.set(prefix, [i]);
      });
      const seen = new Map<string, number>();
      const run = { failed: false };
      let done = 0;
      onProgress?.(0, distinct.length);
      await Promise.all(
        [...byPrefix].map(async ([prefix, members]) => {
          let found = cache.get(prefix);
          if (!found) {
            found = await request(prefix, signal, run);
            cache.set(prefix, found);
          }
          for (const i of members) seen.set(distinct[i], found.get(hashes[i].slice(5)) ?? 0);
          done += members.length;
          if (!run.failed) onProgress?.(done, distinct.length);
        }),
      );
      return seen;
    },
    clear() {
      stop.abort();
      stop = new AbortController();
      ranges = new Map();
    },
  };
}
