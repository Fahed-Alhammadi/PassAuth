import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles/app.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import init from "./wasm/passauth_core";
import { App } from "./App";
import { boot } from "./lib/vault";
import { applyTheme } from "./lib/prefs";

applyTheme();

const root = document.getElementById("root")!;

/** Shown when the encryption module can't load: without it nothing else works. */
function showStartupError(e: unknown) {
  console.error(e);
  root.replaceChildren();
  const main = document.createElement("main");
  main.className = "auth";
  main.innerHTML = `<div class="auth-card"><div class="auth-panel stack" role="alert">
    <h1>PassAuth couldn't start</h1>
    <p>This page couldn't load its encryption module. Check your connection and reload. If you use a reverse proxy or a content filter, make sure it allows <span class="mono">.wasm</span> files.</p>
    <button type="button" class="btn btn-accent btn-block">Reload</button>
  </div></div>`;
  main.querySelector("button")!.addEventListener("click", () => location.reload());
  root.append(main);
}

try {
  await init();
  // boot() never throws: an unreachable server shows a retry screen inside the app.
  await boot();
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
} catch (e) {
  showStartupError(e);
}
