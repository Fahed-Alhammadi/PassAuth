/** Commands to content scripts (chrome.tabs.sendMessage), typed by shared/protocol.ts `ContentCommandApi`. */
import type { ContentCommandApi, Message, ResOf } from "../shared/protocol";

/** One frame: by its document id when known (a navigated frame then gets nothing), else by its frame id. */
export type FrameTarget = { frameId: number; documentId?: string | undefined };

/**
 * Send a command to the tab (default: every frame) or to one frame of it. Rejects when nothing receives it (no
 * content script there: a browser page, a tab still loading, an extension that was just updated).
 */
export function toTab<K extends keyof ContentCommandApi>(tabId: number, command: Message<ContentCommandApi, K>, target?: FrameTarget): Promise<ResOf<ContentCommandApi, K> | undefined> {
  const options = target === undefined ? undefined : target.documentId ? { documentId: target.documentId } : { frameId: target.frameId };
  return chrome.tabs.sendMessage(tabId, command, options) as Promise<ResOf<ContentCommandApi, K> | undefined>;
}

/** The same, when it doesn't matter whether anything received it (the page may have no content script, or was closed). */
export function toTabQuietly<K extends keyof ContentCommandApi>(tabId: number, command: Message<ContentCommandApi, K>, target?: FrameTarget): Promise<void> {
  return toTab(tabId, command, target).then(
    () => {},
    () => {},
  );
}

export const TOP_FRAME: FrameTarget = { frameId: 0 };
