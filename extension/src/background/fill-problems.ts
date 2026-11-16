/**
 * Why the last fill asked for on a tab's page didn't work (the inline menu, the right-click menu or the fill
 * shortcut, whose notes inside the page never say why), kept per tab in session storage (`fillProblem:<tab>`:
 * extension-private, memory-only; the reason names at most a login's websites, never a password or a code). The
 * popup shows it at the top for that tab. It goes when the tab navigates or closes, after a fill that worked there,
 * and after 30 minutes.
 */
import { messageOf } from "../shared/errors";
import { FILL_PROBLEM_PREFIX } from "../shared/storage-keys";
import { type Expiring, store } from "./pending";

interface FillProblem extends Expiring {
  reason: string;
  /** The tab's address when it happened (without the fragment). */
  url: string;
}

const problems = store<FillProblem>(FILL_PROBLEM_PREFIX);
const KEEP_MS = 30 * 60_000;
const MAX_REASON = 300;

const withoutHash = (url: string) => url.replace(/#.*$/, "");

/** A fill on tab `tabId` failed with `e`. */
export async function noteFillProblem(tabId: number, e: unknown) {
  const reason = messageOf(e).replace(/\s+/g, " ").trim().slice(0, MAX_REASON);
  const url = (await chrome.tabs.get(tabId).catch(() => null))?.url ?? "";
  if (!reason || !url) return;
  await problems.put(tabId, { reason, url: withoutHash(url), expires: Date.now() + KEEP_MS });
}

/** The tab navigated or closed, or a fill there worked. */
export const forgetFillProblem = (tabId: number) => problems.remove(tabId);

/** Why the last fill on tab `tabId` didn't work, while it still shows the page `url` it happened on. */
export async function fillProblem(tabId: number, url: string): Promise<string | undefined> {
  const p = await problems.get(tabId);
  return p && typeof p.reason === "string" && p.url === withoutHash(url) ? p.reason : undefined;
}
