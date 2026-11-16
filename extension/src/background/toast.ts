/** Short notes inside a web page (top frame), e.g. "Login saved for example.com." Only page-safe text (shared/page-text.ts). */
import type { PageSafeText } from "../shared/page-text";
import { getSettings } from "./storage";
import { TOP_FRAME, toTabQuietly } from "./tabs";

export async function notifyTab(tabId: number, text: PageSafeText) {
  const { theme } = await getSettings();
  await toTabQuietly(tabId, { type: "toast", text, theme }, TOP_FRAME);
}
