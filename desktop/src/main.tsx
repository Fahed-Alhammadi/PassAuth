import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@web/styles/app.css";
import "./desktop.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import init from "@web/wasm/passauth_core";
import { applyTheme, onThemeChange } from "@web/lib/prefs";
import { registerDesktop } from "@web/lib/platform";
import { installOtpLinks } from "./AddCode";
import { Root } from "./Root";
import { hooks } from "./hooks";
import { installBridge } from "./bridge";
import { scheduleUpdateCheck } from "./updater";

// Title bar and native dialogs follow the vault's theme setting.
onThemeChange((theme) => void getCurrentWindow().setTheme(theme === "system" ? null : theme));
applyTheme();
registerDesktop(await hooks());
installBridge();
scheduleUpdateCheck();

const root = document.getElementById("root")!;
try {
  await init();
  // Parsing a link needs the wasm module.
  void installOtpLinks().catch((e) => console.error(e));
  createRoot(root).render(
    <StrictMode>
      <Root />
    </StrictMode>,
  );
} catch (e) {
  console.error(e);
  root.innerHTML = `<main class="auth"><div class="auth-card"><div class="auth-panel stack" role="alert">
    <h1>PassAuth couldn't start</h1><p>The encryption module didn't load. Reinstall the app, then try again.</p></div></div></main>`;
}
