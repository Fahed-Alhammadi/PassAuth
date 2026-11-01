/** Clipboard writes from the service worker, via an offscreen document. */
import { getSettings } from "./storage";

let creating: Promise<void> | null = null;

async function ensureDocument() {
  const url = chrome.runtime.getURL("offscreen.html");
  const existing = await chrome.runtime.getContexts({ contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT], documentUrls: [url] });
  if (existing.length) return;
  creating ??= chrome.offscreen
    .createDocument({ url, reasons: [chrome.offscreen.Reason.CLIPBOARD], justification: "Copy vault values and clear the clipboard afterwards." })
    .finally(() => (creating = null));
  await creating;
}

/** Copy text and clear it after the user's "Clear clipboard" delay. */
export async function copy(text: string) {
  const { clearClipboard } = await getSettings();
  await ensureDocument();
  await chrome.runtime.sendMessage({ target: "offscreen", text, clearAfter: clearClipboard });
}
