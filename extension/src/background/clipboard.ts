/**
 * Clipboard writes from the background. Chrome's service worker has no DOM, so copies run in an offscreen document
 * (offscreen.html), which also keeps the timer for the clear. Firefox has no offscreen API, but its background is an
 * event page with a DOM: it writes the clipboard itself, and the clear is an alarm (the page can be unloaded while
 * idle, which drops a plain timer).
 */
import type { Message, OffscreenApi } from "../shared/protocol";
import { getSettings } from "./storage";

export const CLIPBOARD_ALARM = "clipboard-clear";

let creating: Promise<void> | null = null;
let clearTimer: ReturnType<typeof setTimeout> | undefined;

/** The few DOM pieces the clipboard needs (the worker's type library has no DOM; Firefox's event page has one). */
interface MiniElement {
  value: string;
  select(): void;
  remove(): void;
}
interface MiniCopyEvent {
  clipboardData: { setData(type: string, text: string): void } | null;
  preventDefault(): void;
}
interface MiniDocument {
  body: { append(el: MiniElement): void } | null;
  createElement(tag: "textarea"): MiniElement;
  addEventListener(type: "copy", fn: (e: MiniCopyEvent) => void, opts?: { once: boolean }): void;
  removeEventListener(type: "copy", fn: (e: MiniCopyEvent) => void): void;
  execCommand(command: "copy"): boolean;
}
const dom = () => (globalThis as unknown as { document?: MiniDocument }).document;

/** Whether the background has a DOM (Firefox's event page) and writes the clipboard itself. */
const hasDom = () => !!dom()?.body;

async function ensureDocument() {
  const url = chrome.runtime.getURL("offscreen.html");
  const existing = await chrome.runtime.getContexts({ contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT], documentUrls: [url] });
  if (existing.length) return;
  creating ??= chrome.offscreen.createDocument({ url, reasons: [chrome.offscreen.Reason.CLIPBOARD], justification: "Copy vault values and clear the clipboard afterwards." }).finally(() => {
    creating = null;
  });
  await creating;
}

/** Writes `text` with the page's own copy command (same as offscreen.html): the copy handler sets the exact text, so "" clears. */
function writeHere(text: string) {
  const document = dom();
  if (!document?.body) return;
  const ta = document.createElement("textarea");
  ta.value = text || " ";
  document.body.append(ta);
  ta.select();
  const onCopy = (e: MiniCopyEvent) => {
    e.clipboardData?.setData("text/plain", text);
    e.preventDefault();
  };
  document.addEventListener("copy", onCopy, { once: true });
  document.execCommand("copy");
  document.removeEventListener("copy", onCopy);
  ta.remove();
}

/** Copy text and clear it after the user's "Clear clipboard" delay. */
export async function copy(text: string) {
  const { clearClipboard } = await getSettings();
  if (hasDom()) {
    writeHere(text);
    clearTimeout(clearTimer);
    await chrome.alarms.clear(CLIPBOARD_ALARM);
    if (clearClipboard > 0) {
      // On time while the page stays loaded; the alarm still clears after an unload.
      clearTimer = setTimeout(() => writeHere(""), clearClipboard * 1000);
      await chrome.alarms.create(CLIPBOARD_ALARM, { delayInMinutes: clearClipboard / 60 });
    }
    return;
  }
  await ensureDocument();
  await chrome.runtime.sendMessage({ type: "offscreen:copy", text, clearAfter: clearClipboard } satisfies Message<OffscreenApi, "offscreen:copy">);
}

/** The clear alarm (Firefox): empties the clipboard. */
export function onClipboardAlarm(alarm: chrome.alarms.Alarm) {
  if (alarm.name === CLIPBOARD_ALARM && hasDom()) writeHere("");
}
