/**
 * Offscreen document (reason CLIPBOARD): the service worker has no DOM, so
 * copies and the timed clipboard clear run here. It outlives the popup, so the
 * clear still happens after the popup closes.
 */
import type { Message, OffscreenApi } from "../shared/protocol";

let clearTimer: ReturnType<typeof setTimeout> | undefined;

function write(text: string) {
  const ta = document.createElement("textarea");
  ta.value = text || " ";
  document.body.append(ta);
  ta.select();
  // The copy handler sets the exact text, so clearing can write an empty string.
  const onCopy = (e: ClipboardEvent) => {
    e.clipboardData?.setData("text/plain", text);
    e.preventDefault();
  };
  document.addEventListener("copy", onCopy, { once: true });
  document.execCommand("copy");
  document.removeEventListener("copy", onCopy);
  ta.remove();
}

const isCopy = (msg: unknown): msg is Message<OffscreenApi, "offscreen:copy"> => {
  const m = msg as Partial<Message<OffscreenApi, "offscreen:copy">> | null;
  return !!m && m.type === "offscreen:copy" && typeof m.text === "string" && typeof m.clearAfter === "number";
};

chrome.runtime.onMessage.addListener((msg: unknown, sender, respond) => {
  // Every extension page hears runtime messages. Only the service worker may
  // write the clipboard (content scripts also have this extension's id).
  if (!isCopy(msg) || sender.id !== chrome.runtime.id || sender.tab || sender.url !== chrome.runtime.getURL("background.js")) return false;
  write(msg.text);
  clearTimeout(clearTimer);
  if (msg.clearAfter > 0) clearTimer = setTimeout(() => write(""), msg.clearAfter * 1000);
  respond(true);
  return false;
});
