/** Native → web: menu and tray actions, and locking when the window stays hidden. (Root tells the tray the vault state.) */
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { getState, lock } from "@web/lib/vault";
import { changeServer } from "./hooks";
import { checkForUpdates } from "./updater";

const HIDDEN_LOCK_MS = 15 * 60 * 1000;

const lockNow = () => {
  if (getState().status === "unlocked") lock(false);
};

/** The web vault's router follows popstate, so a native "Settings…" can navigate without a React handle. */
function navigateTo(path: string) {
  history.pushState(null, "", path);
  dispatchEvent(new PopStateEvent("popstate"));
}

export function installBridge() {
  void listen("lock", lockNow);
  void listen("change-server", () => void changeServer());
  void listen("settings", () => navigateTo("/settings"));
  void listen("check-updates", () => checkForUpdates(true).catch(() => {}));

  // Hidden or minimised for 15 minutes: lock, even if the idle timer was reset just before.
  let hiddenTimer: number | undefined;
  const onVisibility = (hidden: boolean) => {
    clearTimeout(hiddenTimer);
    if (hidden) hiddenTimer = window.setTimeout(lockNow, HIDDEN_LOCK_MS);
  };
  document.addEventListener("visibilitychange", () => onVisibility(document.visibilityState === "hidden"));
  void listen("window-hidden", () => onVisibility(true));
  void getCurrentWindow().onFocusChanged(({ payload: focused }) => focused && onVisibility(false));
}
