/**
 * The address a document stands for when PassAuth decides what it may fill, offer or save there:
 * - its own http(s) URL, when its origin is that URL's origin;
 * - for about:blank and about:srcdoc frames (a page writes those itself, and they inherit its origin), the origin
 *   they inherited, as `origin/` (so only websites saved without a path match them);
 * - otherwise null: sandboxed frames (origin "null"), data: documents and any other scheme get nothing.
 * The background applies the same rule to the browser's sender information (background/sites.ts `webFrame`).
 */
export function pageUrl(): string | null {
  const origin = self.origin;
  if (!origin || !/^https?:\/\/[^/]+$/.test(origin)) return null;
  const { protocol } = location;
  if (protocol === "http:" || protocol === "https:") return origin === location.origin ? location.href : null;
  if (protocol === "about:" && /^about:(blank|srcdoc)$/.test(location.href.replace(/[?#].*$/, ""))) return `${origin}/`;
  return null;
}
