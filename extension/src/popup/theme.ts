import type { Settings } from "../shared/messages";

/** Light/dark choice from Settings → Appearance ("system" follows the OS). */
export function applyTheme(theme: Settings["theme"]) {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
}

/** Apply the saved theme before the first paint. */
export async function loadTheme() {
  const { settings } = await chrome.storage.local.get("settings");
  applyTheme((settings as Partial<Settings> | undefined)?.theme ?? "system");
}
