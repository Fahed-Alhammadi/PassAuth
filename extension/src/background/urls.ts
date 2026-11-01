/** Website matching for autofill. */
import type { LoginUrl, UrlMatch } from "@web/lib/types";

// Common multi-label public suffixes. Not the full Public Suffix List: for
// hosts under other multi-label suffixes "domain" matching falls back to the
// last two labels, which can over-match (e.g. two sites under the same
// regional suffix). Use "host" matching on such items.
const MULTI = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
  "com.br", "com.cn", "com.hk", "com.sg", "com.tr", "com.mx", "com.ar", "co.in", "co.za", "co.kr",
  "com.sa", "net.sa", "gov.sa", "co.ae", "gov.ae", "com.eg", "com.qa", "com.kw", "com.bh", "com.om",
  "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com", "azurewebsites.net",
  "cloudfront.net", "appspot.com", "web.app", "firebaseapp.com",
]);

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
  const labels = h.split(".");
  const last2 = labels.slice(-2).join(".");
  if (MULTI.has(last2) && labels.length >= 3) return labels.slice(-3).join(".");
  return last2;
}

/** Does the page URL match a saved website? `fallback` resolves "default" (the user's setting). */
export function matchesUrl(page: string, item: LoginUrl, fallback: Exclude<UrlMatch, "default"> = "domain"): boolean {
  const p = parse(page);
  if (!p || !/^https?:$/.test(p.protocol)) return false;
  const match = item.match === "default" ? fallback : item.match;
  if (match === "never") return false;
  if (match === "regex") {
    try {
      return new RegExp(item.url, "i").test(page);
    } catch {
      return false;
    }
  }
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
