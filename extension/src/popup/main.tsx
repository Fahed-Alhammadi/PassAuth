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

// Lets the background run the "Immediately" vault timeout when the popup closes.
chrome.runtime.connect({ name: "popup" });

const passkey = location.hash.match(/^#passkey=(.+)$/)?.[1];
await loadTheme();
createRoot(document.getElementById("root")!).render(passkey ? <PasskeyConfirm requestId={passkey} /> : <App />);
