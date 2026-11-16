/**
 * Which site a frame stands for, and the sites where the user hid PassAuth's inline menu.
 * - `webFrame`: the browser's sender information, with about:blank and about:srcdoc frames (which a page writes
 *   itself, and which inherit its origin) standing for that origin, as `origin/`. Their real origin comes from the
 *   browser, never from the frame, so senders.ts then checks them like any other frame; sandboxed frames (origin
 *   "null"), data: documents and frames whose origin doesn't match their URL are left as they are and refused there.
 *   The content script applies the same rule to itself (content/origin.ts).
 * - Hidden sites: base domains in `hiddenSites` (chrome.storage.local), added by "Hide on this site" in the inline
 *   menu; no icon or menu shows there (Settings → Autofill lists them and can show them again).
 */
import type { SenderInfo } from "./senders";
import { baseDomain } from "./site";
import { local } from "./storage";

/** At most this many hidden sites are kept (the oldest go first). */
const MAX_HIDDEN = 500;

const INHERITS = /^about:(blank|srcdoc)(?:[?#]|$)/;

/** `sender`, with an about:blank or about:srcdoc frame standing for the http(s) origin the browser says it has. */
export function webFrame<S extends SenderInfo>(sender: S): S {
  const origin = sender.origin;
  if (!sender.url || !INHERITS.test(sender.url) || !origin || !/^https?:\/\/[^/]+$/.test(origin)) return sender;
  return { ...sender, url: `${origin}/` };
}

/** Whether the inline menu is hidden on the site of `host`. */
export function isHidden(hidden: readonly string[], host: string): boolean {
  return !!host && hidden.includes(baseDomain(host));
}

/** "Hide on this site": the site of `host` gets no inline menu any more. Returns the base domain hidden. */
export async function hideSite(host: string): Promise<string> {
  const site = baseDomain(host);
  if (!site) return site;
  await local.update((l) => (l.hiddenSites.includes(site) ? null : { hiddenSites: [...l.hiddenSites, site].slice(-MAX_HIDDEN) }));
  return site;
}
