/** What the web vault asks the desktop app to do for it (see web/src/lib/platform.ts). */
import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { toast } from "@web/components/ui";
import { forgetSecrets, type DesktopHooks } from "@web/lib/platform";
import { getState, logout } from "@web/lib/vault";
import { confirmChangeServer, requestChangeServer } from "./Root";
import { secrets } from "./secrets";
import { checkForUpdates, installUpdate } from "./updater";

const isMac = navigator.platform.startsWith("Mac");

/** Sign out and forget everything of this server kept in the WebView, so nothing of it is used on the next one. */
export async function changeServer() {
  if (getState().status !== "logged-out" && !(await confirmChangeServer())) return;
  await logout();
  forgetSecrets();
  Object.keys(localStorage)
    .filter((k) => k.startsWith("pa."))
    .forEach((k) => localStorage.removeItem(k));
  requestChangeServer();
}

export async function hooks(): Promise<DesktopHooks> {
  return {
    version: await getVersion(),
    lockShortcut: isMac ? "⌘L" : "Ctrl+L",
    changeServer,
    checkForUpdates,
    installUpdate,
    async saveFile(filename, content) {
      try {
        const saved = await invoke<boolean>("save_file", { filename, content });
        if (saved) toast("Saved");
        return saved;
      } catch {
        toast("Couldn't save the file. Choose another folder.");
        return false;
      }
    },
    copySecret: (value) => invoke("copy_secret", { value }),
    openUrl: (url) => openUrl(url),
    secrets,
  };
}
