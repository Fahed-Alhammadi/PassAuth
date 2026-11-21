/**
 * Who sent a runtime message, from what the browser says about the sender
 * (never from the message itself). Pure; unit-tested in test/senders.test.ts.
 */
import type { LoginUrl, UrlMatch } from "@web/lib/types";
import { baseDomain, downgrade, matchesUrl, parse } from "./site";

export interface SenderInfo {
  id?: string;
  url?: string;
  origin?: string;
  frameId?: number;
  documentId?: string;
  tab?: { id?: number; url?: string };
}

/**
 * The web origin of the document that sent a message, or null when it can't
 * be used for site checks: an opaque origin ("null": sandboxed frames, data:
 * documents, even when their URL looks like the site's), an origin that
 * differs from the frame's URL (about:blank and srcdoc frames borrow their
 * creator's), or anything but http(s).
 */
export function senderOrigin(sender: SenderInfo): string | null {
  const origin = sender.origin;
  if (!origin || origin === "null" || !/^https?:\/\//.test(origin)) return null;
  const url = parse(sender.url ?? "");
  if (!url || !/^https?:$/.test(url.protocol) || url.origin !== origin) return null;
  return origin;
}

/** The page URL of a sender whose origin checks out (see `senderOrigin`), else null. */
export function senderUrl(sender: SenderInfo): URL | null {
  return senderOrigin(sender) ? parse(sender.url ?? "") : null;
}

/** The tab's top-level site, and whether `sender`'s document is on it (by its real origin). */
export function sameSiteAsTab(sender: SenderInfo): boolean {
  const top = parse(sender.tab?.url ?? "");
  const frame = senderUrl(sender);
  return !!top && !!frame && /^https?:$/.test(top.protocol) && baseDomain(top.hostname) === baseDomain(frame.hostname);
}

/**
 * Which of PassAuth's own pages sent a message (its path, e.g. "/popup.html"),
 * or null for anything else (content scripts run in web pages and have web
 * URLs). `ownOrigins`: the extension's origins, including the per-session one
 * of pages loaded through a dynamic URL (web_accessible_resources `use_dynamic_url`).
 */
export function extensionPage(sender: SenderInfo, runtimeId: string, ownOrigins: readonly string[]): string | null {
  if (sender.id !== runtimeId || !sender.url) return null;
  let u: URL;
  try {
    u = new URL(sender.url);
  } catch {
    return null;
  }
  if ((u.protocol !== "chrome-extension:" && u.protocol !== "moz-extension:") || !ownOrigins.includes(extensionOrigin(u.href))) return null;
  return u.pathname;
}

/** Who sent a message: one of PassAuth's own pages, or a content script. */
export type SenderKind = "popup" | "inline" | "save" | "content" | "offscreen" | "other";

const PAGES = new Map<string, SenderKind>([
  // The popup, the pop-out window and the passkey confirmation window are all popup.html.
  ["/popup.html", "popup"],
  ["/inline-menu.html", "inline"],
  ["/save-prompt.html", "save"],
  ["/offscreen.html", "offscreen"],
]);

/**
 * The kind of context that sent a message: one of PassAuth's own pages (by path), else a content script (it runs in
 * a web page and carries that page's URL; the background checks its origin wherever it matters).
 */
export function senderKind(sender: SenderInfo, runtimeId: string, ownOrigins: readonly string[]): SenderKind {
  const page = extensionPage(sender, runtimeId, ownOrigins);
  return page === null ? "content" : (PAGES.get(page) ?? "other");
}

/** "chrome-extension://<host>" of an extension URL (spelled out: `URL.origin` of a non-web scheme isn't the same everywhere). */
export function extensionOrigin(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host}`;
}

/**
 * Whether a frame that claimed a fill may get the secrets: an http(s) document
 * whose real origin matches its URL, on the tab's site, that the login's
 * websites match (same rules as the top frame, no https → http downgrade). A
 * login without websites only fills on the tab's own site.
 */
export function frameMayFill(sender: SenderInfo, urls: LoginUrl[], defaultMatch: Exclude<UrlMatch, "default">, topSite: string, allowRegex: boolean): boolean {
  const frame = senderUrl(sender);
  if (!frame) return false;
  const href = frame.href;
  if (!urls.length) return baseDomain(frame.hostname) === topSite;
  return urls.some((u) => matchesUrl(href, u, defaultMatch, allowRegex)) && !urls.some((u) => downgrade(href, u));
}
