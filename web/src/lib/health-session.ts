/**
 * Password health for the unlocked vault in this page session; `health.ts` does the work. The report is worked out
 * again only when the vault changes. The breach check runs only when the user asks and the server allows it (feature
 * `breach_check`), with the browser's own `fetch` (the desktop app's native client only reaches the PassAuth server).
 * The report, the check's results and the kept range answers stay in memory and are dropped when the vault locks or
 * signs out.
 */
import { useEffect, useState, useSyncExternalStore } from "react";
import { hasFeature, loadPublicConfig, type PublicConfig } from "./api";
import { analyze, BreachCheckError, createBreachChecker, PWNED_ORIGIN, type HealthReport } from "./health";
import { isDesktop } from "./platform";
import type { VaultEntry } from "./types";
import { estimateBits, getState, onVaultChange, useVault } from "./vault";

// -------------------------------------------------------------------- report

let memo: { items: VaultEntry[]; report: HealthReport<VaultEntry> } | null = null;

/** Weak and reused passwords among `items`; the same array gives back the same report. */
export function healthReport(items: VaultEntry[]): HealthReport<VaultEntry> {
  if (memo?.items !== items) memo = { items, report: analyze(items, estimateBits) };
  return memo.report;
}

/** The report for the vault as it is now (every vault the user can read). */
export const useHealthReport = () => healthReport(useVault().items);

// -------------------------------------------------------------- breach check

/**
 * Announced in GET /api/config `features` while the server's admin setting allows the breach check; the server's
 * Content-Security-Policy then lets the web vault reach Have I Been Pwned. The desktop app follows it too.
 */
export const BREACH_CHECK_FEATURE = "breach_check";

/** `unknown`: the server's settings couldn't be loaded. */
export type BreachCheckAvailability = "loading" | "on" | "off" | "unknown";

/** Whether this server allows the breach check (its settings are fetched once per server and page). */
export function useBreachCheckAvailability(): BreachCheckAvailability {
  const [config, setConfig] = useState<PublicConfig | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    loadPublicConfig().then((c) => live && setConfig(c));
    return () => {
      live = false;
    };
  }, []);
  if (config === undefined) return "loading";
  if (config === null) return "unknown";
  return hasFeature(config, BREACH_CHECK_FEATURE) ? "on" : "off";
}

export interface BreachCheck {
  status: "idle" | "checking" | "done" | "failed";
  /** While checking: distinct passwords checked so far, of `total`. */
  done: number;
  total: number;
  /** Times seen in data breaches per password, from the last finished check; passwords added or changed since are missing. */
  results: ReadonlyMap<string, number> | null;
  /** When `results` came in (ms since the epoch). */
  checkedAt: number | null;
  /** Why the last check stopped, in plain words. */
  error: string | null;
}

const IDLE: BreachCheck = { status: "idle", done: 0, total: 0, results: null, checkedAt: null, error: null };
let current = IDLE;
const subs = new Set<() => void>();

function publish(next: BreachCheck) {
  current = next;
  subs.forEach((fn) => fn());
}
const update = (patch: Partial<BreachCheck>) => publish({ ...current, ...patch });
const subscribe = (fn: () => void) => {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
};

export const getBreachCheck = () => current;
export const useBreachCheck = () => useSyncExternalStore(subscribe, getBreachCheck);

const checker = createBreachChecker((url, init) => fetch(url, init));
/** Bumped when the vault locks or signs out: a check started before that is dropped. */
let generation = 0;

onVaultChange(() => {
  if (getState().status === "unlocked") return;
  memo = null;
  if (current === IDLE) return;
  generation++;
  checker.clear();
  publish(IDLE);
});

/**
 * Check the password of every login the user can read against Have I Been Pwned, if the server allows it. A previous
 * check's results stay until this one finishes. Never throws.
 */
export async function checkForBreaches(): Promise<void> {
  if (current.status === "checking" || getState().status !== "unlocked") return;
  const gen = generation;
  const fail = (error: string) => {
    if (gen === generation) update({ status: "failed", error });
  };
  update({ status: "checking", done: 0, total: 0, error: null });
  const config = await loadPublicConfig();
  if (!hasFeature(config, BREACH_CHECK_FEATURE)) return fail(config ? MESSAGES.notAllowed : MESSAGES.noConfig);
  if (navigator.onLine === false) return fail(MESSAGES.offline);
  const vault = getState();
  if (gen !== generation || vault.status !== "unlocked") return;
  const passwords = new Set(healthReport(vault.items).logins.map((e) => e.item.login?.password ?? ""));
  update({ total: passwords.size });
  const csp = watchCsp();
  try {
    const results = await checker.check(passwords, (done, total) => {
      if (gen === generation) update({ done, total });
    });
    if (gen === generation) update({ status: "done", results, checkedAt: Date.now() });
  } catch (e) {
    fail(await explain(e, csp));
  } finally {
    csp.stop();
  }
}

const MESSAGES = {
  notAllowed: "This server doesn't allow checking passwords against Have I Been Pwned.",
  noConfig: "Couldn't load your server's settings. Check your connection, then try again.",
  offline: "You're offline. Connect to the internet, then try again.",
  unreachable: "Couldn't reach Have I Been Pwned. Check your connection, VPN or content blocker, then try again.",
  blockedWeb:
    "This page's Content-Security-Policy blocks api.pwnedpasswords.com. If a reverse proxy sets its own policy, allow that address in its connect-src, then try again.",
  blockedDesktop: "This app's Content-Security-Policy blocks api.pwnedpasswords.com. Update the app, then try again.",
  timeout: "Have I Been Pwned didn't answer in time. Try again in a moment.",
  busy: "Have I Been Pwned is busy. Wait a minute, then try again.",
  invalid: "The answer didn't come from Have I Been Pwned. If this network shows a sign-in page, sign in there first, then try again.",
  insecure: "This check needs a secure connection. Open PassAuth at its https:// address, then try again.",
  stopped: "The check stopped. Try again.",
};

/** Notes Content-Security-Policy violations for Have I Been Pwned while a check runs. */
function watchCsp() {
  const watch = { blocked: false, stop: () => document.removeEventListener("securitypolicyviolation", note) };
  function note(e: SecurityPolicyViolationEvent) {
    if (e.blockedURI.startsWith(PWNED_ORIGIN)) watch.blocked = true;
  }
  document.addEventListener("securitypolicyviolation", note);
  return watch;
}

async function explain(e: unknown, csp: { blocked: boolean }): Promise<string> {
  if (!(e instanceof BreachCheckError)) return MESSAGES.stopped;
  switch (e.reason) {
    case "network":
      // A blocked request fails at once; its violation event can arrive just after.
      await new Promise((resolve) => setTimeout(resolve, 50));
      if (csp.blocked) return isDesktop() ? MESSAGES.blockedDesktop : MESSAGES.blockedWeb;
      return navigator.onLine === false ? MESSAGES.offline : MESSAGES.unreachable;
    case "timeout":
      return MESSAGES.timeout;
    case "http":
      return e.status === 429 ? MESSAGES.busy : `Have I Been Pwned couldn't answer (error ${e.status}). Try again later.`;
    case "invalid":
      return MESSAGES.invalid;
    case "insecure":
      return MESSAGES.insecure;
  }
}
