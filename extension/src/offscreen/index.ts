/**
 * Offscreen document (reason CLIPBOARD): the service worker has no DOM, so
 * copies and the timed clipboard clear run here. It outlives the popup, so the
 * clear still happens after the popup closes.
 */
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

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  // Every extension page hears runtime messages; answer only our own.
  if (msg?.target !== "offscreen" || sender.id !== chrome.runtime.id) return false;
  write(msg.text);
  clearTimeout(clearTimer);
  if (msg.clearAfter > 0) clearTimer = setTimeout(() => write(""), msg.clearAfter * 1000);
  respond(true);
  return false;
});
