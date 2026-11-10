import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@web/styles/app.css";
import "./popup.css";

import { createRoot } from "react-dom/client";
import { App } from "./App";
import { PasskeyConfirm } from "./Passkey";
import { loadTheme } from "./theme";
import { fitWindow, POPUP_WINDOW } from "../shared/windows";

// Lets the background run the "Immediately" vault timeout when the popup closes.
// The heartbeat keeps the service worker awake while a PassAuth window is open
// (e.g. a passkey confirmation); if the worker was stopped anyway, reconnect.
function keepAlive() {
  const port = chrome.runtime.connect({ name: "popup" });
  const beat = setInterval(() => port.postMessage("beat"), 20_000);
  port.onDisconnect.addListener(() => {
    clearInterval(beat);
    setTimeout(keepAlive, 100);
  });
}
keepAlive();

const passkey = location.hash.match(/^#passkey=(.+)$/)?.[1];
const popout = new URLSearchParams(location.search).has("popout");
if (popout) document.documentElement.classList.add("popout");
// The confirmation window is exactly as tall as its sheet (Passkey.tsx sizes it).
if (passkey) document.documentElement.classList.add("sheet-window");
await loadTheme();
createRoot(document.getElementById("root")!).render(passkey ? <PasskeyConfirm requestId={passkey} /> : <App />);
// PassAuth in its own window (pop-out, unlock): the page area the popup was designed for, whatever the OS frame is.
if (popout && !passkey) void fitWindow(() => POPUP_WINDOW);
