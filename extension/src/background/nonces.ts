/**
 * The inline menu and the save prompt are extension pages framed inside web
 * pages. Each gets a nonce (by postMessage, after it loaded) that ties it to
 * its tab; the first frame that uses a nonce owns it (tab, frame and document),
 * so a copy of the nonce in another frame gets nothing. In memory for the
 * moment two frames race; the record (`recorded`) keeps the owner across a
 * worker restart.
 */
import type { FrameTarget } from "./tabs";

type Sender = chrome.runtime.MessageSender;

const redeemed = new Map<string, string>();
const frameKey = (tabId: number | undefined, f: FrameTarget) => `${tabId}:${f.frameId}:${f.documentId ?? ""}`;

/** The frame (and document) `sender` is. */
export const thisFrame = (sender: Sender): FrameTarget => ({ frameId: sender.frameId ?? -1, ...(sender.documentId ? { documentId: sender.documentId } : {}) });

/** Whether `sender` owns `nonce`: it is the first frame to use it (then it becomes the owner) or the recorded owner. */
export function ownsNonce(nonce: string, sender: Sender, recorded: FrameTarget | undefined): boolean {
  const me = frameKey(sender.tab?.id, thisFrame(sender));
  const first = redeemed.get(nonce) ?? (recorded ? frameKey(sender.tab?.id, recorded) : undefined);
  if (first === undefined) {
    if (redeemed.size > 200) redeemed.clear();
    redeemed.set(nonce, me);
    return true;
  }
  return first === me;
}

/** The nonce was used up. */
export function forgetNonce(nonce: string) {
  redeemed.delete(nonce);
}
