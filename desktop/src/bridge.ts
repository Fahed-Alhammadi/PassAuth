/** Native → web: menu and tray actions. (Root tells the tray the vault state; `timeout.ts` locks by itself.) */
import { listen } from "@tauri-apps/api/event";
import { getState, lock } from "@web/lib/vault";
import { changeServer } from "./hooks";
import { clearPersistedKeys } from "./timeout";
import { checkForUpdates } from "./updater";

/** "Lock Vault" (menu, tray, ⌘L): always a lock, and the keys kept for "never" are removed from the keychain. */
const lockNow = async () => {
  if (getState().status !== "unlocked") return;
  lock(false);
  await clearPersistedKeys();
};

/** The web vault's router follows popstate, so a native "Settings…" can navigate without a React handle. */
export function navigateTo(path: string) {
  history.pushState(null, "", path);
  dispatchEvent(new PopStateEvent("popstate"));
}

export function installBridge() {
  void listen("lock", lockNow);
  void listen("change-server", () => void changeServer());
  void listen("settings", () => navigateTo("/settings"));
  void listen("check-updates", () => checkForUpdates(true).catch(() => {}));
}
