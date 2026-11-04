/** Website matching for autofill. */
import type { LoginUrl, UrlMatch } from "@web/lib/types";
import { publicSuffixOf } from "./psl.ts";

// Registrable domain ("site") for "domain" matching uses the shared suffix
// list in psl.ts. It is not the full Public Suffix List: hosts under an
// unlisted multi-label suffix fall back to the last two labels, which can
// over-match. Use "host" matching on such items.

export function parse(url: string): URL | null {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`);
  } catch {
    return null;
  }
}

export function baseDomain(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (/^[\d.]+$/.test(h) || h.includes(":") || !h.includes(".")) return h;
  const suffix = publicSuffixOf(h);
  if (!suffix) return h.split(".").slice(-2).join(".");
  // One label more than the public suffix ("home.duckdns.org"); a bare suffix stays as it is.
  const labels = h.split(".");
  const n = suffix.split(".").length + 1;
  return labels.slice(-Math.min(n, labels.length)).join(".");
}

/** Longest regex pattern PassAuth evaluates (patterns come from shared vaults too). */
export const MAX_REGEX_LENGTH = 300;

/**
 * Patterns likely to backtrack catastrophically: a quantified group that itself
 * contains a quantifier, e.g. "(a+)+" or "(.*a){10}". They are not evaluated.
 */
export function unsafeRegex(pattern: string): boolean {
  return pattern.length > MAX_REGEX_LENGTH || /\([^)]*[+*}][^)]*\)\s*[+*{]/.test(pattern);
}

/** Regex "match" tests only the page's origin and path (no query or fragment, so "?bank.com" can't satisfy it). */
function regexMatches(pattern: string, page: URL): boolean {
  if (unsafeRegex(pattern)) return false;
  try {
    return new RegExp(pattern, "i").test((page.origin + page.pathname).slice(0, 2048));
  } catch {
    return false;
  }
}

/** Does the page URL match a saved website? `fallback` resolves "default" (the user's setting). */
export function matchesUrl(page: string, item: LoginUrl, fallback: Exclude<UrlMatch, "default"> = "domain"): boolean {
  const p = parse(page);
  if (!p || !/^https?:$/.test(p.protocol)) return false;
  const match = item.match === "default" ? fallback : item.match;
  if (match === "never") return false;
  if (match === "regex") return regexMatches(item.url, p);
  const u = parse(item.url);
  if (!u) return false;
  switch (match) {
    case "exact":
      return p.href === u.href;
    case "starts_with":
      return p.href.startsWith(u.href);
    case "host":
      return p.host === u.host;
    default:
      return baseDomain(p.hostname) === baseDomain(u.hostname);
  }
}

/** Refuse to send a secret saved for an https site to an http page. */
export function downgrade(page: string, item: LoginUrl): boolean {
  if (item.match === "regex") return /^http:/i.test(page) && !/^https?:\/\/localhost[:/]/i.test(page) && /^\^?https:/i.test(item.url);
  const p = parse(page);
  const u = parse(item.url);
  return !!p && !!u && u.protocol === "https:" && p.protocol === "http:" && p.hostname !== "localhost";
}
